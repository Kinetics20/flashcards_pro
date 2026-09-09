Operations
==========

Configuration
-------------

Settings are read from ``APP_`` environment variables and an optional ``.env``
file. Unknown ``APP_`` names fail startup. Production mode rejects enabled API
documentation.

Health probes
-------------

``/health/live`` proves that the process can answer HTTP requests.
``/health/ready`` indicates whether the instance should receive traffic. Add
checks for required local resources to readiness when introducing them. Avoid
removing a healthy replica from load solely because a transient downstream
integration is unavailable.

Logging
-------

Logs are JSON on standard output. A validated incoming ``X-Request-ID`` is
preserved; an absent or unsafe value is replaced with a UUID. The same ID is
added to responses, access logs, error responses, and can be propagated to
outbound HTTP calls with ``outbound_correlation_headers``.

Containers
----------

The container runs as an unprivileged user on port 8000. The supplied Compose
service uses a read-only root filesystem and a temporary ``/tmp`` mount.
