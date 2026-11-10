# ATTILAN

`attilan` — controlled criminal-intelligence provenance ledger for local deployments.

## ARCHITECTURE

```text
browser
  | TLS 1.3
nginx_gateway
  |-- /api --> fastapi_engine (api_worker transaction role)
  |-- /     --> frontend_ui (UID 10001)
  |
  +--> db_core
        |- db_owner             NOLOGIN: schema + trigger ownership
        |- api_worker           NOLOGIN: SELECT / INSERT / UPDATE only (bounded via RLS)
        |- api_worker_login     LOGIN: SET LOCAL ROLE api_worker
        |- audit_reader         NOLOGIN: SELECT audit_merkle_ledger only
        `- audit_replica_login  LOGIN: SET ROLE audit_reader

fastapi_engine --> MinIO WORM object storage (Via isolated service account 'attilan_api', No Root)
hash_broadcaster --read-only--> Sequential Hash Chain Ledger (Batch limit 50, re-verified) --> remote checkpoint
```

## SECURITY BOUNDARIES

| Boundary | Limit |
| :--- | :--- |
| Cryptographic Hashing | SHA-256 and BLAKE3 prove byte identity. They do not establish real-world truth. |
| Quarantine Intake | Submissions without validated authentication routing rest immutably in AWAITING_VERIFICATION state inside the quarantine_intake block. |
| 4-Eyes Authority | SAME_AS graph edges require strictly distinct authorization tokens (CHECK authorized_by_key_1 != authorized_by_key_2). |
| Full Envelope Hash | Ledger audit verification incorporates leaf index, timestamp, action type, table, actor, IP, payload digest, and previous hash sequentially. |
| Storage Independence | API utilizes non-root scoped credentials and stream chunks payloads; DB triggers govern idempotency independent of object lock completion. |
| Database Superuser | Trigger limits halt api_worker_login. Postgres superuser destruction relies strictly on continuous HMAC-off-box broadcaster checkpointing for forensic detection. |
| Export | Returns UNCERTIFIED_RAW_DIGEST_MANIFEST. Automatically generates a read-access ledger audit. Hardware-HSM workflow requires external offline verification. |

## LOCAL PROCEDURE

```sh
cp .env.example .env
# Replace every CHANGE_ME value with URL-safe cryptographic material.
docker compose -f docker-compose.prod.yml config
docker compose -f docker-compose.prod.yml build --pull
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
curl --fail --silent --show-error https://localhost/health
```

Issue a JWT through the authorized identity provider. Requirements: UUID sub, exp, iat, strict iss and aud, explicit clearances array.

```sh
curl --fail --silent --show-error \
  --header "Authorization: Bearer $ATTILAN_JWT" \
  "https://localhost/api/export/certificate/$SOURCE_UUID?format=markdown"
```

## INTEGRITY CHECKS

```sh
python -m pip install --no-cache-dir -r backend/requirements.txt
export JWT_SECRET_KEY='ci-cryptographic-material-placeholder'
export JWT_ISSUER='attilan-core-idp'
export JWT_AUDIENCE='attilan-core-client'
export DATABASE_URL='postgresql://api_worker_login:ci_worker_password@localhost:5432/opencase_test'
pytest backend/tests -q
npm --prefix frontend ci
npm --prefix frontend run build
```

## OPERATIONS

```sh
docker compose -f docker-compose.prod.yml logs --tail=100 fastapi_engine hash_broadcaster
docker compose -f docker-compose.prod.yml exec db_core \
  psql -U "$DB_BOOTSTRAP_USER" -d "$POSTGRES_DB" -c '\du api_worker audit_reader'
docker compose -f docker-compose.prod.yml exec db_core \
  psql -U "$DB_BOOTSTRAP_USER" -d "$POSTGRES_DB" -c '\dp audit_merkle_ledger'
```

