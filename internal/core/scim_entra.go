package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Entra ID's default SCIM dialect predates its aadOptscim062020 compliance
// flag: it matches resources by externalId before every write, sends only
// what changed as path PATCH operations with capitalized op values, sends
// active as the string "True" or "False", and sends the manager as a bare
// ID.

// entraMatchError reports a resource that Entra ID's externalId match did
// not find before an update.
func (c *SCIMClient) entraMatchError(resourceType string, externalID string) error {
	err := fmt.Errorf("SCIM %s with externalId %q: %w", resourceType, externalID, errSCIMNotFound)
	c.setLastTraceError(err)
	return err
}

// patchEntraUser updates remote with the attributes of u that differ from
// it. It sends nothing when they match.
func (c *SCIMClient) patchEntraUser(u User, directory scimUserDirectory, remote SCIMUserResource) error {
	operations := entraUserOperations(newSCIMUserResource(u, directory), remote)
	if len(operations) == 0 {
		return nil
	}
	return c.doJSON(http.MethodPatch, "/Users/"+url.PathEscape(remote.ID), newSCIMPathPatchRequest(operations), nil, traceTargetForUser(u, "update"))
}

// patchEntraGroup renames remote and adds or removes only the members that
// changed. It sends nothing when the group matches.
func (c *SCIMClient) patchEntraGroup(g Group, users []User, remote SCIMGroupResource) error {
	desired, err := newSCIMGroupResource(g, users)
	if err != nil {
		return err
	}
	operations := entraGroupOperations(desired, remote)
	if len(operations) == 0 {
		return nil
	}
	return c.doJSON(http.MethodPatch, "/Groups/"+url.PathEscape(remote.ID), newSCIMPathPatchRequest(operations), nil, traceTargetForGroup(g, "update"))
}

func newSCIMPathPatchRequest(operations []scimPatchOperation) scimPatchRequest {
	return scimPatchRequest{Schemas: []string{scimPatchSchema}, Operations: operations}
}

func entraUserOperations(desired SCIMUserResource, remote SCIMUserResource) []scimPatchOperation {
	var operations []scimPatchOperation
	set := func(path string, want string, have string) {
		switch {
		case want == strings.TrimSpace(have):
		case want == "":
			operations = append(operations, scimPatchOperation{Op: "Remove", Path: path})
		default:
			operations = append(operations, scimPatchOperation{Op: "Replace", Path: path, Value: want})
		}
	}
	desiredGiven, desiredFamily := scimNameParts(desired.Name)
	remoteGiven, remoteFamily := scimNameParts(remote.Name)
	set("userName", desired.UserName, remote.UserName)
	set("displayName", desired.DisplayName, remote.DisplayName)
	set("name.givenName", desiredGiven, remoteGiven)
	set("name.familyName", desiredFamily, remoteFamily)
	set(`emails[type eq "work"].value`, firstSCIMEmail(desired.Emails), firstSCIMEmail(remote.Emails))
	set("externalId", desired.ExternalID, remote.ExternalID)
	if remoteActive := remote.Active == nil || *remote.Active; *desired.Active != remoteActive {
		operations = append(operations, scimPatchOperation{Op: "Replace", Path: "active", Value: entraBool(*desired.Active)})
	}
	if desired.Enterprise == nil {
		return operations
	}
	remoteEnterprise := remote.Enterprise
	if remoteEnterprise == nil {
		remoteEnterprise = &SCIMEnterpriseUser{}
	}
	prefix := scimEnterpriseUserSchema + ":"
	set(prefix+"employeeNumber", desired.Enterprise.EmployeeNumber, remoteEnterprise.EmployeeNumber)
	set(prefix+"costCenter", desired.Enterprise.CostCenter, remoteEnterprise.CostCenter)
	set(prefix+"organization", desired.Enterprise.Organization, remoteEnterprise.Organization)
	set(prefix+"division", desired.Enterprise.Division, remoteEnterprise.Division)
	set(prefix+"department", desired.Enterprise.Department, remoteEnterprise.Department)
	set(prefix+"manager", scimManagerValue(desired.Enterprise.Manager), scimManagerValue(remoteEnterprise.Manager))
	return operations
}

func entraGroupOperations(desired SCIMGroupResource, remote SCIMGroupResource) []scimPatchOperation {
	var operations []scimPatchOperation
	if desired.DisplayName != strings.TrimSpace(remote.DisplayName) {
		operations = append(operations, scimPatchOperation{Op: "Replace", Path: "displayName", Value: desired.DisplayName})
	}
	remoteMembers := make(map[string]bool, len(remote.Members))
	for _, member := range remote.Members {
		remoteMembers[strings.TrimSpace(member.Value)] = true
	}
	desiredMembers := make(map[string]bool, len(desired.Members))
	var added []SCIMMember
	for _, member := range desired.Members {
		desiredMembers[member.Value] = true
		if !remoteMembers[member.Value] {
			added = append(added, SCIMMember{Value: member.Value})
		}
	}
	var removed []SCIMMember
	for _, member := range remote.Members {
		if value := strings.TrimSpace(member.Value); !desiredMembers[value] {
			removed = append(removed, SCIMMember{Value: value})
		}
	}
	if len(added) > 0 {
		operations = append(operations, scimPatchOperation{Op: "Add", Path: "members", Value: added})
	}
	if len(removed) > 0 {
		operations = append(operations, scimPatchOperation{Op: "Remove", Path: "members", Value: removed})
	}
	return operations
}

// entraBool spells a boolean the way Entra ID sends active.
func entraBool(value bool) string {
	if value {
		return "True"
	}
	return "False"
}
