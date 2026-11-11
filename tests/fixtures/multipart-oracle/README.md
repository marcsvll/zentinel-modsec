# Multipart oracle fixtures

`cases/*.json` are multipart bodies (Content-Type and raw body); `expected/*.json` is what
ModSecurity v3 (libmodsecurity 3.0.17 in the OWASP CRS project's nginx image) produced for
each: body arguments, files and the `REQBODY_ERROR` / `MULTIPART_*` flags. They are written
by `conformance/multipart-oracle/run.sh` in the neblina repository and copied here; the unit
tests in `src/variables/request.rs` (`multipart_oracle`) assert the parser against them.
