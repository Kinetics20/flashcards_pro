Architecture
============

The application uses feature-oriented vertical slices. Cross-cutting runtime
and HTTP behavior lives under ``core`` and ``http``; business capabilities live
under ``modules``.

Dependency direction
--------------------

The normal dependency flow is ``router -> schema -> service -> repository``.
Services contain use cases and do not import FastAPI. Repositories contain
persistence operations and do not create HTTP responses. The HTTP dependency
layer composes concrete adapters at the edge.

Application lifecycle
---------------------

``app.main.create_app`` builds the application and creates the optional database
and telemetry runtimes. The FastAPI lifespan verifies the enabled database
connection before accepting traffic.

Shutdown always closes the database runtime and flushes telemetry providers,
including when application startup fails.

HTTP boundary
-------------

Health probes are unversioned because they describe the process. Public
business endpoints are mounted below ``/api/v1``. Global middleware assigns a
safe request ID, emits one structured access record, bounds request bodies, and
applies CORS only when explicitly configured.

Application exceptions are translated into a stable public error envelope.
Unexpected exceptions are logged once and hidden from the client.
