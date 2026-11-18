#!/bin/sh
# postgres-entrypoint.sh — Automates role reconciliation on container boot.
# Guarantees POSTGRES_USER from .env always exists even on pre-initialized volumes.
set -e

(
  # Wait for postgres daemon to accept connections
  until pg_isready -q 2>/dev/null; do
    sleep 0.5
  done

  # Reconcile configured bootstrap user
  if [ -n "$POSTGRES_USER" ]; then
    # Test if POSTGRES_USER exists and can authenticate
    if ! psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1" >/dev/null 2>&1; then
      echo "[postgres-entrypoint] Configured user '$POSTGRES_USER' missing in initialized volume. Reconciling..."
      
      # Find which superuser role exists to perform the creation
      ADMIN_USER=""
      for candidate in attilan_admin attilan_bootstrap postgres; do
        if psql -U "$candidate" -d "$POSTGRES_DB" -c "SELECT 1" >/dev/null 2>&1; then
          ADMIN_USER="$candidate"
          break
        fi
      done

      if [ -n "$ADMIN_USER" ]; then
        psql -U "$ADMIN_USER" -d "$POSTGRES_DB" -c "
          DO \$\$
          BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$POSTGRES_USER') THEN
              CREATE ROLE \"$POSTGRES_USER\" WITH SUPERUSER LOGIN PASSWORD '$POSTGRES_PASSWORD';
            ELSE
              ALTER ROLE \"$POSTGRES_USER\" WITH SUPERUSER LOGIN PASSWORD '$POSTGRES_PASSWORD';
            END IF;
          END
          \$\$;
        " >/dev/null 2>&1
        echo "[postgres-entrypoint] Role '$POSTGRES_USER' successfully created and synced."
      else
        echo "[postgres-entrypoint] Warning: could not find active admin role to create '$POSTGRES_USER'."
      fi
    else
      # User exists; synchronize password if POSTGRES_PASSWORD is provided
      if [ -n "$POSTGRES_PASSWORD" ]; then
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
          ALTER ROLE \"$POSTGRES_USER\" WITH PASSWORD '$POSTGRES_PASSWORD';
        " >/dev/null 2>&1 || true
      fi
    fi
  fi
) &

if [ $# -eq 0 ]; then
  set -- postgres
fi

exec docker-entrypoint.sh "$@"
