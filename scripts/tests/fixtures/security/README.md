# Synthetic policy fixtures

These reports exercise the policy evaluator, not vulnerability discovery.
Identifiers and package names are synthetic. No vulnerable package is installed.
Artifact hashes are placeholders for in-memory tests; complete evidence tests
create actual artifacts in temporary directories and calculate their digests.

Integration tests run real scanners separately and verify their expected rule or
advisory identifiers. Synthetic secret values are assembled only at test runtime.
