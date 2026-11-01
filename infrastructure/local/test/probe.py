"""A real, one-shot HTTP smoke check; no fake long-running test service."""

import json
import urllib.request

for path in ("/health/live", "/health/ready", "/api/v1/status"):
    with urllib.request.urlopen("http://gateway:8080" + path, timeout=5) as response:
        assert response.status == 200
        assert json.load(response)["status"] == "ok"
with urllib.request.urlopen(
    "http://keycloak:8080/auth/realms/flashcards/.well-known/openid-configuration", timeout=5
) as response:
    assert response.status == 200
    assert json.load(response)["issuer"].endswith("/auth/realms/flashcards")
print("Gateway, Content readiness and development OIDC discovery passed")
