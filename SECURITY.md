# Security policy

This branch (`neblina/patches`) is the rule engine of the neblina WAF and is developed
as that project's own code. A request that the loaded rules should detect and the engine
lets through, or one that makes the engine panic, hang or use unbounded memory, is a
security issue of this branch whether or not upstream `zentinel-modsec` has it.

Report it by email to <marcus@paledoor.io>; ask for an encrypted channel in the first
message if you need one. Do not open a public issue or pull request for a suspected
vulnerability. Include the commit or `neblina-engine-v*` tag, the rules (or the CRS
version and paranoia level) and a request that reproduces the problem.

Fixes land here as commits with a regression test and are offered upstream once public.
