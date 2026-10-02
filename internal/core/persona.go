package core

import "strings"

const (
	// PersonaGeneric issues scimtest's own claim and SCIM shapes.
	PersonaGeneric = "generic"
	// PersonaEntra shapes claims and SCIM requests like Microsoft Entra ID.
	PersonaEntra = "entra"
	// PersonaOkta shapes claims like Okta.
	PersonaOkta = "okta"
	// PersonaGoogle shapes claims like Google.
	PersonaGoogle = "google"
)

// DefaultGroupsOverageThreshold is the most groups Entra ID puts in a JWT
// before it switches to the overage form.
const DefaultGroupsOverageThreshold = 200

// NormalizePersona returns a supported persona, defaulting to Generic.
func NormalizePersona(persona string) string {
	switch persona = strings.TrimSpace(persona); persona {
	case PersonaEntra, PersonaOkta, PersonaGoogle:
		return persona
	default:
		return PersonaGeneric
	}
}

// GroupsOverageThresholdForApp returns the app's Entra ID groups overage
// threshold, or the default when none is set.
func GroupsOverageThresholdForApp(app App) int {
	if app.GroupsOverageThreshold > 0 {
		return app.GroupsOverageThreshold
	}
	return DefaultGroupsOverageThreshold
}
