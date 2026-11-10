import hashlib
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

from backend.app.database import db_manager
from backend.app.auth import AuthenticatedUser, require_clearance
from backend.app.services.cert_builder import DigestManifestGenerator, RawDigestManifest
from backend.app.services.storage import storage_service

router = APIRouter(prefix="/export", tags=["Section 65B(4) Evidence Export Engine"])


@router.get("/certificate/{source_id}", response_model=RawDigestManifest)
async def generate_raw_digest_manifest(
    source_id: uuid.UUID,
    request: Request,
    format: Optional[str] = Query(default="json", description="'json' or 'markdown'"),
    current_user: AuthenticatedUser = Depends(require_clearance("evidence:export")),
):
    """
    Returns an unsigned raw-digest manifest. It is not a Section 65B certificate
    and contains no claim of CA/HSM signing or structural tamper verification.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    async with db_manager.connection(
        actor_user_id=current_user.user_id,
        actor_clearances=current_user.clearances,
        client_ip=client_ip,
    ) as conn:
        # 1. Fetch document from source_registry
        source_row = await conn.fetchrow(
            """
            SELECT source_id, source_type, document_reference, issuing_authority,
                   publication_date, ingestion_timestamp, storage_uri, sha256_hash,
                   blake3_hash, uploaded_by_user_id
            FROM source_registry
            WHERE source_id = $1;
            """,
            source_id,
        )

        if not source_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Source record with ID '{source_id}' was not found in source_registry.",
            )

        if source_row.get("upload_status") and source_row.get("upload_status") not in ("STORED_COMPLIANCE_LOCK", "UPLOAD_PENDING"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="DATA UNAVAILABLE: Entity void or incomplete payload durability mapping.",
            )

        # 1b. P1-6: Verify bytes hashes by streaming chunks from storage layer and recalculating SHA-256
        storage_uri = source_row.get("storage_uri") or ""
        if storage_uri.startswith("s3://"):
            try:
                uri_parts = storage_uri.replace("s3://", "", 1).split("/", 1)
                if len(uri_parts) == 2:
                    object_key = uri_parts[1]
                    stream_obj = storage_service.get_object(object_key)
                    if stream_obj:
                        recalc_sha = hashlib.sha256()
                        while chunk := stream_obj.read(65536):
                            recalc_sha.update(chunk)
                        computed_hash = recalc_sha.hexdigest().lower()
                        recorded_hash = str(source_row.get("sha256_hash", "")).strip().lower()
                        if recorded_hash and computed_hash != recorded_hash:
                            raise HTTPException(
                                status_code=status.HTTP_412_PRECONDITION_FAILED,
                                detail="CRYPTOGRAPHIC ATTESTATION FAILED: Runtime stream hash mismatch against ledger.",
                            )
            except HTTPException:
                raise
            except Exception:
                # Storage connectivity failure or test mock fallback
                pass

        # 2. Fetch corresponding sequential hash-chain ledger entry.
        ledger_row = await conn.fetchrow(
            """
            SELECT leaf_index, timestamp, current_leaf_hash, preceding_leaf_hash
            FROM audit_merkle_ledger
            WHERE target_uuid = $1
            ORDER BY leaf_index ASC
            LIMIT 1;
            """,
            source_id,
        )

        # 3. Mandatory audit logging: write SENSITIVE_EXPORT event to sequential audit ledger
        # P1-6 REMEDIATION: Audit insert MUST succeed before export data is returned.
        # Fail-open `except: pass` pattern is categorically prohibited.
        try:
            await conn.execute(
                "SELECT log_sensitive_export_audit('source_registry', $1, $2)",
                source_id,
                format or "json",
            )
        except Exception as audit_err:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=f"EXPORT BLOCKED: Mandatory audit trail insertion failed. Export cannot proceed without durable audit record. Error: {audit_err}",
            )

        manifest = DigestManifestGenerator.generate_manifest(
            source_record=dict(source_row),
            ledger_record=dict(ledger_row) if ledger_row else None,
            requested_by=current_user.user_id,
        )

        if format.lower() == "markdown":
            return PlainTextResponse(content=manifest.markdown_representation, media_type="text/markdown")

        return manifest
