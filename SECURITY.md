# Security Policy & Evidentiary Assurance Architecture

## Scope and Principles
Attilan is engineered to process highly sensitive legal records, law enforcement intelligence, and public-interest evidentiary data within high-adversity environments. Design constraints follow strict statutory mandates for cryptographic digital admissibility and jurisdictional data protection directives. 

## 1. Epistemic Limits of Cryptography

System architecture bifurcates **Data Integrity** and **Data Veracity**:
- **Data Integrity**: Guaranteed mathematically via dual SHA-256 / BLAKE3 chunking, MinIO Object Lock (Compliance Mode), and sequential full-envelope ledger checks (`audit_merkle_ledger`).
- **Data Veracity**: Software cannot cryptographically dictate truth. Intake boundaries enforce this by pushing raw public submission into `quarantine_intake`. UI layers enforce absolute epistemological watermarking (e.g., `PRE-TRIAL ALLEGATION - NOT JUDICIALLY PROVEN`) for unadjudicated material.

## 2. Adversarial Threat Model & Remediation Status

### RT-01: Fabricated Lawfare Ingestion
- **Vector**: Hostile inputs masquerading as valid judicial records for targeted character assault.
- **Control**: Submission states fail safely into the durable `quarantine_intake` pool with an `AWAITING_VERIFICATION` badge. Judicial flags (Acquittal/Conviction) are mathematically disabled without verified out-of-band registrar authorization mapped to a physical case binding. 

### RT-02: Rogue Administrator DB Mutiny 
- **Vector**: A compromised user truncates/drops audit traces or overwrites identities. 
- **Control**: All criminal datasets carry Row-Level Security masking. While API triggers deter ordinary user meddling, Postgres Superusers *can* bypass RLS constraints. Absolute mutiny detection is therefore guaranteed exclusively via out-of-band monitoring: the read-only daemon reconstructs sequence chains and dispatches to independent physical nodes, creating immediate collision logs upon silent deletion. 

### RT-04: Automated Algorithmic Disambiguation Failure 
- **Vector**: Name collapsers automatically flag and overwrite non-identical subjects. Missing parameters simulate positive similarity values.
- **Control**: Zero algorithmic slop; alias normalization enforces strict mapping checks absent false equivalence mapping. Missing structural queries default explicitly to `INSUFFICIENT_DATA`. Valid links demand human dual-authorization checked exclusively by POSTGRES schemas enforcing mathematically distinct origin identities.

### RT-09: Silent Edge Extrusion / Bulk Payload Download 
- **Vector**: Trusted API accounts parse out complete database dossiers.
- **Control**: `/api/export` writes persistent event audit footprints before fetching Object records. NGINX imposes IP rate limits coupled with bounded RAM stream chunk buffering to isolate service health during extraction anomalies.

### RT-10: Asynchronous Tampering Sequence Breach
- **Vector**: Operators alter ledger indices and concurrently kill hash broadcasters before daemon pushes updates. 
- **Control**: Bounded batch fetches enforce validation locally; full cryptographic sequential hash generation completes prior to payload MAC issuance. Durable non-tmpfs file system states ensure checkpoint logic restarts idempotently without replaying void intervals.

## 3. Operations Transport Boundaries
- TLS 1.3 Strict implementation across edge.
- S3 integration enforces separate least-privilege tokens isolating Root. 
- Application Health checks enforce dual real-time read validations (DB_Ping/Bucket_Ping); failing fast prevents decoupled runtime desynchronization.

## 4. Reporting Instructions
Do NOT deploy findings natively in Github Issues. Escalate critical cryptographic compromises safely via `tazwardevp@gmail.com`. Format standard PoC structures dictating module sequence breakdown (nginx_gateway, db_core, hash_broadcaster, etc.). Acknowledgment < 48 hrs.
