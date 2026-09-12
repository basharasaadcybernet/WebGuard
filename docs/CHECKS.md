# Security Checks

No posture checks are implemented in milestones 1–3.

Future rules will use stable dotted identifiers, including:

- `transport.https_available`
- `headers.content_security_policy`
- `cookies.secure`
- `hygiene.security_txt`

Rules will inspect observations supplied by the scanner. They must not create raw HTTP clients or
make direct network requests.
