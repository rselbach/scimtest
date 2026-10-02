package core

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Enterprise attribute names follow the SCIM enterprise user extension
// (RFC 7643 section 4.3). OIDC claims and SAML attributes use the same names.
const (
	EnterpriseEmployeeNumber = "employeeNumber"
	EnterpriseCostCenter     = "costCenter"
	EnterpriseOrganization   = "organization"
	EnterpriseDivision       = "division"
	EnterpriseDepartment     = "department"
	EnterpriseManager        = "manager"
)

const (
	maxCustomAttributes           = 50
	maxCustomAttributeNameLength  = 128
	maxCustomAttributeValueLength = 1024
)

// customAttributeNamePattern admits plain names and URI-style names such as
// SAML claim types.
var customAttributeNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:/#-]*$`)

// reservedAttributeNames are protocol claims that scimtest sets itself, and
// the enterprise names, which have their own fields.
var reservedAttributeNames = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
	"jti": true, "nonce": true, "auth_time": true, "acr": true, "amr": true,
	"azp": true, "at_hash": true, "c_hash": true, "s_hash": true, "sid": true,
	"cnf": true, "client_id": true, "scope": true, "events": true,
	"_claim_names": true, "_claim_sources": true,
	EnterpriseEmployeeNumber: true, EnterpriseCostCenter: true,
	EnterpriseOrganization: true, EnterpriseDivision: true,
	EnterpriseDepartment: true, EnterpriseManager: true,
}

// NamedValue is one attribute name and its value.
type NamedValue struct {
	Name  string
	Value string
}

// EnterpriseValues returns the user's enterprise string values in schema
// order. The manager is a user reference, so callers resolve it separately.
func EnterpriseValues(u User) []NamedValue {
	return []NamedValue{
		{Name: EnterpriseEmployeeNumber, Value: u.EmployeeNumber},
		{Name: EnterpriseCostCenter, Value: u.CostCenter},
		{Name: EnterpriseOrganization, Value: u.Organization},
		{Name: EnterpriseDivision, Value: u.Division},
		{Name: EnterpriseDepartment, Value: u.Department},
	}
}

// HasEnterpriseValues reports whether any enterprise field, including the
// manager, is set.
func HasEnterpriseValues(u User) bool {
	if u.ManagerID != "" {
		return true
	}
	for _, value := range EnterpriseValues(u) {
		if value.Value != "" {
			return true
		}
	}
	return false
}

// UserManager returns u's manager when ManagerID names a user that exists
// and is not deleted.
func UserManager(users []User, u User) (User, bool) {
	if u.ManagerID == "" {
		return User{}, false
	}
	manager, ok := UserByID(users, u.ManagerID)
	if !ok || manager.Deleted {
		return User{}, false
	}
	return manager, true
}

// CustomAttributeNames returns the attribute names in sorted order, so claims
// and assertion attributes come out the same way every time.
func CustomAttributeNames(attributes map[string]string) []string {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsReservedAttributeName reports whether name is a protocol claim or an
// enterprise field name that a custom attribute must not use.
func IsReservedAttributeName(name string) bool {
	return reservedAttributeNames[name]
}

// ValidateManager checks a newly chosen manager for the user with userID.
// Callers skip it when the manager is unchanged, so deleting a manager does
// not block unrelated edits to their reports.
func ValidateManager(users []User, userID string, managerID string) error {
	switch managerID {
	case "":
		return nil
	case userID:
		return fmt.Errorf("a user cannot be their own manager")
	}
	if _, ok := UserManager(users, User{ManagerID: managerID}); !ok {
		return fmt.Errorf("manager %q is not a user in this environment", managerID)
	}
	return nil
}

// ValidateCustomAttributes checks custom attribute names and values.
func ValidateCustomAttributes(attributes map[string]string) error {
	if len(attributes) > maxCustomAttributes {
		return fmt.Errorf("a user can have at most %d custom attributes", maxCustomAttributes)
	}
	for _, name := range CustomAttributeNames(attributes) {
		value := attributes[name]
		switch {
		case len(name) > maxCustomAttributeNameLength:
			return fmt.Errorf("custom attribute name %q is longer than %d characters", name, maxCustomAttributeNameLength)
		case !customAttributeNamePattern.MatchString(name):
			return fmt.Errorf("custom attribute name %q must start with a letter or underscore and use only letters, digits, and _ . : / # -", name)
		case IsReservedAttributeName(name):
			return fmt.Errorf("custom attribute name %q is reserved", name)
		case len(value) > maxCustomAttributeValueLength:
			return fmt.Errorf("custom attribute %q is longer than %d characters", name, maxCustomAttributeValueLength)
		case strings.ContainsAny(value, "\r\n"):
			return fmt.Errorf("custom attribute %q must be a single line", name)
		}
	}
	return nil
}

// ParseCustomAttributes reads one name=value pair per line. Blank lines are
// skipped, and an empty result is nil.
func ParseCustomAttributes(text string) (map[string]string, error) {
	var attributes map[string]string
	for number, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("custom attribute on line %d must look like name=value", number+1)
		}
		name = strings.TrimSpace(name)
		if _, exists := attributes[name]; exists {
			return nil, fmt.Errorf("custom attribute %q is listed more than once", name)
		}
		if attributes == nil {
			attributes = make(map[string]string)
		}
		attributes[name] = strings.TrimSpace(value)
	}
	return attributes, nil
}

// FormatCustomAttributes writes attributes as sorted name=value lines, the
// form ParseCustomAttributes reads.
func FormatCustomAttributes(attributes map[string]string) string {
	lines := make([]string, 0, len(attributes))
	for _, name := range CustomAttributeNames(attributes) {
		lines = append(lines, name+"="+attributes[name])
	}
	return strings.Join(lines, "\n")
}
