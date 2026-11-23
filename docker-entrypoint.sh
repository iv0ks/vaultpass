#!/bin/sh
# Container entrypoint.
#
# docker-compose only starts this service once Postgres reports healthy, but we
# add migrate + seed on every boot anyway. Both are idempotent, so running them
# on each boot is safe and guarantees the lab data is always present and in a
# known state.
set -e

echo "[entrypoint] applying migrations …"
node dist/db/migrate.js

echo "[entrypoint] seeding data …"
node dist/db/seed.js

echo "[entrypoint] starting app …"
exec "$@"
