-- Runs only when this project's PostgreSQL volume is first initialized.
-- psql reads secrets from the environment rather than command-line arguments.
\set ON_ERROR_STOP on
\getenv app_user FCB_DB_APP_USER
\getenv app_password FCB_DB_APP_PASSWORD
\getenv app_database POSTGRES_DB
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
ALTER DATABASE :"app_database" OWNER TO :"app_user";
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
