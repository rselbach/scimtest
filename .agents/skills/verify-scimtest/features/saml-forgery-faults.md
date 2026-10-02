# Inject SAML identity-forgery faults

Three SAML-only tamper faults keep the genuine IdP signature valid while the
posted response asserts a second directory user's identity. `xsw_assertion` and
`xsw_response` place an unsigned forged copy ahead of the signed assertion or
response. `nameid_comment` splits the signed `NameID` with a comment so a naive
first-text-node read returns the forged user. They let an SP team check that
their app rejects XML signature wrapping (the XSW class) and `NameID` comment
injection (CVE-2018-0489 and related). scimtest posts only to the configured
ACS URL.

## Sub-features

- `forgery-user` picks the lowest-ID other active user as the forged identity
  and fails clearly when no second user exists.
- `xsw-assertion` wraps a signed assertion; it needs the assertion signed.
- `xsw-response` wraps a signed response; it needs the response signed.
- `nameid-comment` splits the signed `NameID` and keeps the signature valid.
- `forgery-encryption` refuses to combine any wrapping fault with assertion
  encryption.

## How to get to it (user POV)

- In the SAML Inspector, expand `Simulate a failure` and check a `Signature
  wrapping` or `NameID comment injection` box under `Tamper`, then `Arm for
  next flow`.
- Call `PUT /api/v1/environments/{id}/faults` with a `tamper` array containing
  `xsw_assertion`, `xsw_response`, or `nameid_comment`.
- Add `fault_tamper=nameid_comment` to a Test sign-in URL for a one-shot run.
- Sign in through `/saml/{slug}/sso`, then read the posted response in the SAML
  Inspector or `GET /inspections/saml`.

## Driving it with Browser

Preconditions:

- Greendale Portal has SAML enabled with endpoint name `greendale-portal`, ACS
  URL `https://sp.greendale.test/acs`, and `saml_signing_mode` set to match the
  fault under test (`assertion` or `both` for `xsw_assertion`, `response` or
  `both` for `xsw_response`).
- The directory has at least two active users, Troy Barnes and Abed Nadir.
- Route `https://sp.greendale.test/**` to a stub body so the posted form lands
  somewhere.

- **Arm from the inspector.** Open the SAML Inspector, expand `Simulate a
  failure`, check `NameID comment injection`, and `Arm for next flow`. The
  armed-faults banner names the tamper.
- **Sign in.** Open `/saml/greendale-portal/sso`, select Troy Barnes, and
  choose `Continue`. The browser posts to the stubbed ACS.
- **Check the comment fault.** Decode the newest `EncodedResponse` from `GET
  /inspections/saml`. The `NameID` reads
  `abed@greendale.edu<!---->.scimtest-forged.example`. Its first text node is
  `abed@greendale.edu` (the forged user); the joined text is the unknown
  `.scimtest-forged.example` value. Verify the response with an XML-DSig
  library other than goxmldsig, such as `signxml`, against
  `/saml/greendale-portal/certificate.pem`: the signature still verifies.
- **Wrapping.** Arm `Signature wrapping (signed assertion)` with mode
  `assertion`, or `Signature wrapping (signed response)` with mode `response`,
  and sign in again. The decoded response carries two assertions (or a forged
  response wrapping the signed one). The first assertion a naive reader finds
  names `abed@greendale.edu`; the element that carries the `ds:Signature` still
  verifies and names `troy@greendale.edu`.
- **Needs a second user.** Remove Abed, arm any of the three, and sign in. The
  flow fails with an error that another active directory user is required, and
  nothing is posted.
- **Refuses encryption.** Set `saml_encryption_certificate_pem`, arm a wrapping
  fault, and sign in. The flow fails with an error that wrapping cannot combine
  with assertion encryption.

## Gotchas

- `xsw_assertion` needs the assertion signed and `xsw_response` needs the
  response signed. Arming the wrong one for the signing mode fails the flow with
  a clear error rather than posting a healthy response.
- The forged `NameID` value depends on the environment's `SAMLNameIDField`, so
  it is the other user's username or name field when that is configured.
- A validator that searches the whole document finds the genuine signature even
  when the processed element is forged. Check that the signature verified
  references the element under test, and read the whole `NameID` text node.
