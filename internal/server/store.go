package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rselbach/scimtest/internal/atomicfile"
)

const sessionLifetime = 30 * 24 * time.Hour

type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Sessions            map[string]StoredSession            `json:"sessions"`
	ApplicationProfiles map[string]StoredApplicationProfile `json:"application_profiles"`
}

type StoredSession struct {
	ID        string    `json:"id"`
	Login     string    `json:"login"`
	Admin     bool      `json:"admin"`
	CSRFToken string    `json:"csrf_token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		path = "scimtest-server.json"
	}
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) CreateSession(login string, admin bool) (StoredSession, error) {
	login = normalizeLogin(login)
	if login != "rselbach" || !admin {
		return StoredSession{}, errors.New("dashboard access is restricted to rselbach")
	}
	id, err := randomHex(32)
	if err != nil {
		return StoredSession{}, err
	}
	csrfToken, err := randomHex(32)
	if err != nil {
		return StoredSession{}, err
	}
	now := time.Now().UTC()
	session := StoredSession{
		ID:        id,
		Login:     login,
		Admin:     admin,
		CSRFToken: csrfToken,
		CreatedAt: now,
		ExpiresAt: now.Add(sessionLifetime),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Sessions[id] = session
	if err := s.saveLocked(); err != nil {
		delete(s.data.Sessions, id)
		return StoredSession{}, err
	}
	return session, nil
}

func (s *Store) Session(id string) (StoredSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.data.Sessions[id]
	if !ok {
		return StoredSession{}, false, nil
	}
	if session.Login == "rselbach" && session.Admin && session.CSRFToken != "" && time.Now().UTC().Before(session.ExpiresAt) {
		return session, true, nil
	}
	delete(s.data.Sessions, id)
	if err := s.saveLocked(); err != nil {
		s.data.Sessions[id] = session
		return StoredSession{}, false, err
	}
	return StoredSession{}, false, nil
}

func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.data.Sessions[id]
	delete(s.data.Sessions, id)
	if err := s.saveLocked(); err != nil {
		if exists {
			s.data.Sessions[id] = session
		}
		return err
	}
	return nil
}

type applicationProfileValues struct {
	name                 string
	publicKey            string
	publicKeyFingerprint string
	routes               []StoredApplicationRoute
	requestsPerMinute    int
	requestBurst         int
	concurrentRequests   int
}

func applicationProfileValuesFrom(name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (applicationProfileValues, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return applicationProfileValues{}, errors.New("application name is required")
	}
	if len(name) > applicationNameMaxLength {
		return applicationProfileValues{}, errors.New("application name must be 80 characters or less")
	}
	canonicalKey, _, fingerprint, err := parseEd25519PublicKey(publicKey)
	if err != nil {
		return applicationProfileValues{}, err
	}
	if len(routes) == 0 {
		return applicationProfileValues{}, errors.New("at least one route is required")
	}
	if requestsPerMinute <= 0 || requestBurst <= 0 || concurrentRequests <= 0 {
		return applicationProfileValues{}, errors.New("application limits must be positive")
	}
	return applicationProfileValues{
		name:                 name,
		publicKey:            canonicalKey,
		publicKeyFingerprint: fingerprint,
		routes:               cloneApplicationRoutes(routes),
		requestsPerMinute:    requestsPerMinute,
		requestBurst:         requestBurst,
		concurrentRequests:   concurrentRequests,
	}, nil
}

func (s *Store) CreateApplicationProfile(name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (StoredApplicationProfile, error) {
	values, err := applicationProfileValuesFrom(name, publicKey, routes, requestsPerMinute, requestBurst, concurrentRequests)
	if err != nil {
		return StoredApplicationProfile{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return StoredApplicationProfile{}, err
	}
	profile := StoredApplicationProfile{
		ID:                   id,
		Name:                 values.name,
		PublicKey:            values.publicKey,
		PublicKeyFingerprint: values.publicKeyFingerprint,
		Routes:               values.routes,
		RequestsPerMinute:    values.requestsPerMinute,
		RequestBurst:         values.requestBurst,
		ConcurrentRequests:   values.concurrentRequests,
		Instances:            make(map[string]StoredApplicationInstance),
		CreatedAt:            time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.data.ApplicationProfiles {
		if existing.PublicKey == values.publicKey {
			return StoredApplicationProfile{}, errors.New("public key is already used by another application")
		}
	}
	s.data.ApplicationProfiles[id] = profile
	return cloneApplicationProfile(profile), s.saveLocked()
}

func (s *Store) UpdateApplicationProfile(id, name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (StoredApplicationProfile, error) {
	values, err := applicationProfileValuesFrom(name, publicKey, routes, requestsPerMinute, requestBurst, concurrentRequests)
	if err != nil {
		return StoredApplicationProfile{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[id]
	if !ok {
		return StoredApplicationProfile{}, errors.New("application profile not found")
	}
	for existingID, existing := range s.data.ApplicationProfiles {
		if existingID != id && existing.PublicKey == values.publicKey {
			return StoredApplicationProfile{}, errors.New("public key is already used by another application")
		}
	}
	profile.Name = values.name
	profile.PublicKey = values.publicKey
	profile.PublicKeyFingerprint = values.publicKeyFingerprint
	profile.Routes = values.routes
	profile.RequestsPerMinute = values.requestsPerMinute
	profile.RequestBurst = values.requestBurst
	profile.ConcurrentRequests = values.concurrentRequests
	s.data.ApplicationProfiles[id] = profile
	return cloneApplicationProfile(profile), s.saveLocked()
}

func (s *Store) ApplicationProfile(id string) (StoredApplicationProfile, bool) {
	if !applicationIDRE.MatchString(id) {
		return StoredApplicationProfile{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[id]
	if !ok {
		return StoredApplicationProfile{}, false
	}
	return cloneApplicationProfile(profile), true
}

func (s *Store) ListApplicationProfiles() []StoredApplicationProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	profiles := make([]StoredApplicationProfile, 0, len(s.data.ApplicationProfiles))
	for _, profile := range s.data.ApplicationProfiles {
		profiles = append(profiles, cloneApplicationProfile(profile))
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles
}

func (s *Store) DeleteApplicationProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.ApplicationProfiles[id]; !ok {
		return errors.New("application profile not found")
	}
	delete(s.data.ApplicationProfiles, id)
	return s.saveLocked()
}

// TunnelIDReserved reports whether id is remembered for any application
// instance, so another application instance cannot take the same name.
func (s *Store) TunnelIDReserved(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, profile := range s.data.ApplicationProfiles {
		for _, instance := range profile.Instances {
			if instance.TunnelID == id {
				return true
			}
		}
	}
	return false
}

func (s *Store) ApplicationTunnelID(profileID, instanceID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.ApplicationProfiles[profileID].Instances[instanceID].TunnelID
}

func (s *Store) RememberApplicationTunnel(profileID, instanceID, tunnelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[profileID]
	if !ok {
		return errors.New("application profile not found")
	}
	if profile.Instances == nil {
		profile.Instances = make(map[string]StoredApplicationInstance)
	}
	now := time.Now().UTC()
	for id, instance := range profile.Instances {
		if now.Sub(instance.LastUsedAt) > applicationInstanceMaxIdle {
			delete(profile.Instances, id)
		}
	}
	if _, exists := profile.Instances[instanceID]; !exists && len(profile.Instances) >= applicationInstancesMax {
		return errors.New("application has too many remembered instances")
	}
	instance := profile.Instances[instanceID]
	if instance.CreatedAt.IsZero() {
		instance.CreatedAt = now
	}
	instance.TunnelID = tunnelID
	instance.LastUsedAt = now
	profile.Instances[instanceID] = instance
	s.data.ApplicationProfiles[profileID] = profile
	return s.saveLocked()
}

func (s *Store) UnreserveApplicationTunnel(profileID, instanceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[profileID]
	if !ok {
		return false, nil
	}
	if _, ok := profile.Instances[instanceID]; !ok {
		return false, nil
	}
	delete(profile.Instances, instanceID)
	s.data.ApplicationProfiles[profileID] = profile
	return true, s.saveLocked()
}

func cloneApplicationProfile(profile StoredApplicationProfile) StoredApplicationProfile {
	profile.Routes = cloneApplicationRoutes(profile.Routes)
	instances := profile.Instances
	profile.Instances = make(map[string]StoredApplicationInstance, len(instances))
	for id, instance := range instances {
		profile.Instances[id] = instance
	}
	return profile
}

func cloneApplicationRoutes(routes []StoredApplicationRoute) []StoredApplicationRoute {
	cloned := make([]StoredApplicationRoute, len(routes))
	for i, route := range routes {
		cloned[i] = route
		cloned[i].Methods = append([]string(nil), route.Methods...)
	}
	return cloned
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = storeData{
		Sessions:            make(map[string]StoredSession),
		ApplicationProfiles: make(map[string]StoredApplicationProfile),
	}

	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.NewDecoder(file).Decode(&s.data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if s.data.ApplicationProfiles == nil {
		s.data.ApplicationProfiles = make(map[string]StoredApplicationProfile)
	}
	if s.data.Sessions == nil {
		s.data.Sessions = make(map[string]StoredSession)
	}
	if s.migrateApplicationInstancesLocked() {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) migrateApplicationInstancesLocked() bool {
	changed := false
	for id, profile := range s.data.ApplicationProfiles {
		for instanceID, instance := range profile.Instances {
			if !instance.CreatedAt.IsZero() {
				continue
			}
			instance.CreatedAt = instance.LastUsedAt
			if instance.CreatedAt.IsZero() {
				instance.CreatedAt = profile.CreatedAt
			}
			profile.Instances[instanceID] = instance
			changed = true
		}
		s.data.ApplicationProfiles[id] = profile
	}
	return changed
}

func (s *Store) saveLocked() error {
	return atomicfile.WriteJSON(s.path, s.data)
}

func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
