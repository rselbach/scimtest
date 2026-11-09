# Choose SAML signed parts

SAML setup chooses whether scimtest signs the assertion, the Response, or
both. With encryption, the assertion is signed before it is encrypted and the
Response after, so the Response signature covers the `EncryptedAssertion`.

## Sub-features

- `signing-form` shows the `Signed parts` combobox in SAML setup and keeps the
  saved choice.
- `signing-api` reads and writes `saml_signing_mode` on the environment and
  rejects unknown values.
- `signing-sso` posts a response whose signatures match the choice.
- `signing-encrypted` keeps every signature valid when an SP encryption
  certificate is set.
- `signing-break` makes the broken-signature fault corrupt every signature the
  response carries.

## How to get to it (user POV)

- Open an environment's setup dialog, choose the `SAML` tab, and expand
  `Signing and Encryption`.
- Call `PATCH /api/v1/environments/{id}` with `saml_signing_mode` on the local
  API.
- Sign in through `/saml/{slug}/sso` or `POST
  /api/v1/environments/{id}/saml/sign-in`, then read the response in the SAML
  Inspector or `GET /inspections/saml`.

## Driving it with Browser

Preconditions:

- Greendale Portal has SAML enabled with endpoint name `greendale-portal`, ACS
  URL `https://sp.greendale.test/acs`, and user Troy Barnes.
- Route `https://sp.greendale.test/**` to a stub body so the posted form lands
  somewhere.

- **Read the default.** Open the setup dialog, choose the `SAML` tab, and
  expand `Signing and Encryption`. Combobox `Signed parts` shows `Assertion`.
- **Change it.** Select `Response and assertion` and choose `Save environment`.
  Reopen the dialog. The combobox still shows `Response and assertion`.
  `GET /api/v1/environments/{id}` returns `"saml_signing_mode":"both"`.
- **Sign in.** Open `/saml/greendale-portal/sso`, select Troy Barnes, and
  choose `Continue`. The browser posts to the stubbed ACS.
- **Check the signatures.** Decode the newest `EncodedResponse` from `GET
  /inspections/saml`. Verify it with an XML-DSig library other than
  goxmldsig, such as `signxml`, against
  `/saml/greendale-portal/certificate.pem`. The `Response` and the `Assertion`
  each carry their own `ds:Signature`, placed after `Issuer`, and both verify.
- **Each mode.** Repeat through the API for `assertion`, `response`, and
  `both`. Only the chosen parts carry a signature.
- **Encrypted.** Set `saml_encryption_certificate_pem` to a test SP
  certificate. The Response signature still verifies over the
  `EncryptedAssertion`. Decrypt the assertion with the SP key; its signature
  verifies when the mode includes the assertion.
- **Broken signature.** `PUT /faults` with `break_signature: true`, then sign
  in once with `both`. Every signature present fails verification.

## Gotchas

- A validator that searches the whole document finds the assertion's
  signature when asked about the Response. Check that the signature verified
  references the element under test.
- Disabling SAML clears the signing mode with the rest of the SAML settings.
- The inspector's `Assertion before encryption` block appears only when an
  encryption certificate is set.
