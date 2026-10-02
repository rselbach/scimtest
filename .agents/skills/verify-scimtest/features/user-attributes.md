# Edit user attributes

The user dialog sets a user's enterprise fields, manager, and custom
attributes. OIDC claims and SAML attributes carry them, and SCIM sync sends the
enterprise fields.

## Sub-features

- `attributes-enterprise` saves employee number, department, division,
  organization, and cost center.
- `attributes-manager` picks another user as manager and never offers the user
  being edited.
- `attributes-custom` saves `name=value` lines and rejects malformed lines.
- `attributes-claims` shows the values as ID token claims in the playground.

## How to get to it (user POV)

- On Users, choose `Edit user` in a user's row. `Enterprise attributes` and
  `Custom attributes` open on their own when the user has values.
- On Users, choose `Add user` and expand the same sections.

## Driving it with Browser

Preconditions:

- Greendale Portal has OIDC enabled with client ID `greendale-portal`.
- The Greendale sample is loaded.

- **Open Troy.** Choose `Edit user` in Troy Barnes's row. Dialog `Edit User`
  shows `Enterprise attributes` expanded with Department `Air Conditioning
  Repair` and Manager `Dean Pelton (dean.pelton@greendale.edu)`. `Custom
  attributes` is expanded with `role=student`. The Manager combobox has no
  `Troy Barnes` option. Capture this state.
- **Change values.** Set Department to `Study Room F`, choose Manager `Jeff
  Winger (jeff.winger@greendale.edu)`, and set the attributes to
  `role=student` and `annex=true` on separate lines. Choose `Save user` and
  expect status `user updated`.
- **Confirm persistence.** Reload, open Troy's dialog again, and confirm the
  three changes. Troy's history includes `Updated enterprise attributes`.
- **Reject a malformed line.** Add a line `annex` without `=` and save. The
  dialog stays open with `custom attribute on line 3 must look like
  name=value`, and the typed values remain.
- **Check claims.** Run the OIDC playground as Troy. `id_token_claims` include
  `department: Study Room F`, `manager` equal to Jeff's user ID, `role:
  student`, and `annex: true`.

## Gotchas

- Claims need the `profile` scope. The playground requests it by default.
- Names such as `sub`, `iss`, and `department` are reserved for custom
  attributes, so use other names when testing errors on purpose.
- SCIM sync never sends custom attributes. Check the sync trace for the
  `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` object instead.
