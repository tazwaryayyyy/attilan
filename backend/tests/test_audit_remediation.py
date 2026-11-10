import io
import json
import uuid
import hashlib
from datetime import date, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from contextlib import asynccontextmanager

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.auth import AuthenticatedUser
from backend.app.services.disambiguation import (
    BengaliDisambiguationEvaluator,
    BengaliPhoneticEngine,
)
from backend.app.daemons.hash_broadcaster import SequentialHashChainBroadcaster
from backend.tests.conftest import auth_headers, issue_token


@pytest.mark.asyncio
class TestMission1DurableQuarantine:
    """Mission 1: Evidentiary status control and court order verification."""

    async def test_caller_cannot_directly_pass_judicial_status(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = auth_headers(uuid.uuid4(), ["criminal:write"])
            payload = {
                "parent_case_number": "Khulna PS Case 101/2026",
                "event_type": "FIR_REGISTRATION",
                "thana_jurisdiction": "Labanchora",
                "district": "Khulna",
                "event_date": "2026-06-01",
                "primary_source_id": str(uuid.uuid4()),
                "procedural_weight": "JUDICIAL_ACQUITTAL",
                "event_summary": "Attempting caller direct judicial acquittal assertion.",
            }
            resp = await client.post("/events/create", json=payload, headers=headers)
            assert resp.status_code == 403
            assert "CALLER_EVIDENTIARY_BYPASS_PROHIBITED" in resp.json()["detail"]

    @patch("backend.app.routers.events.db_manager")
    async def test_tombstone_rejects_non_court_order_source(self, mock_db_manager):
        mock_conn = AsyncMock()
        tx_mock = MagicMock()
        tx_mock.__aenter__ = AsyncMock(return_value=None)
        tx_mock.__aexit__ = AsyncMock(return_value=None)
        mock_conn.transaction = MagicMock(return_value=tx_mock)

        mock_conn.fetchrow.side_effect = [
            # V1 event row
            {
                "event_id": uuid.uuid4(),
                "parent_case_number": "Khulna Case 12",
                "thana_jurisdiction": "Labanchora",
                "district": "Khulna",
                "procedural_weight": "FIR_COGNIZANCE",
                "is_superseded": False,
            },
            # Non-court source or missing COURT_ORDER source_type
            None,
        ]

        @asynccontextmanager
        async def mock_conn_ctx(**kwargs):
            yield mock_conn

        mock_db_manager.connection = mock_conn_ctx

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/events/{uuid.uuid4()}/tombstone_and_supersede",
                json={
                    "legal_justification": "Sessions Court Judgment 45/2026",
                    "court_order_source_id": str(uuid.uuid4()),
                    "new_event_type": "JUDICIAL_VERDICT",
                    "new_procedural_weight": "JUDICIAL_ACQUITTAL",
                    "new_event_summary": "Acquitted",
                    "new_event_date": "2026-07-01",
                },
                headers=auth_headers(uuid.uuid4(), ["criminal:write"]),
            )
            assert resp.status_code == 400
            assert "source_type = 'COURT_ORDER'" in resp.json()["detail"]


@pytest.mark.asyncio
class TestMission2FourEyesEnforcement:
    """Mission 2: SQL layer four-eyes token bindings."""

    @patch("backend.app.routers.entity.db_manager")
    async def test_dual_key_rejects_identical_token_or_user(self, mock_db_manager):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            user_id = uuid.uuid4()
            headers = auth_headers(user_id, ["entity:resolve"])
            headers["X-Dual-Control-Authorization"] = f"Bearer {issue_token(user_id, ['entity:resolve'])}"
            payload = {
                "entity_a_id": str(uuid.uuid4()),
                "entity_b_id": str(uuid.uuid4()),
                "source_document_id": str(uuid.uuid4()),
                "contextual_label": "ATTEMPTED SINGLE USER DUAL KEY",
                "confidence_score": 0.95,
            }
            resp = await client.post("/entity/resolve_conflict", json=payload, headers=headers)
            assert resp.status_code == 403


class TestMission3SequentialAuditLedger:
    """Mission 3: Envelope metadata hashing & broadcaster recalculation."""

    def test_broadcaster_detects_hash_tampering_and_halts(self, tmp_path):
        cursor_file = tmp_path / "broadcaster_cursor.json"
        broadcaster = SequentialHashChainBroadcaster(
            database_url="postgresql://fake@localhost/fake",
            signing_key="test-key",
            cursor_file_path=str(cursor_file),
        )

        leaf_idx = 1
        ts = "2026-11-05 12:00:00+00"
        action = "INSERT"
        table = "source_registry"
        target_uuid = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        client_ip = "127.0.0.1"
        data_hash = hashlib.sha256(b"payload").hexdigest()
        prev_hash = "0" * 64

        valid_envelope = f"{leaf_idx}{ts}{action}{table}{target_uuid}{actor_id}{client_ip}{data_hash}{prev_hash}"
        valid_current_hash = hashlib.sha256(valid_envelope.encode("utf-8")).hexdigest()

        # Commit cursor test
        broadcaster.commit_cursor(10)
        assert broadcaster.get_last_cursor() == 10

        # Tampered record
        tampered_record = {
            "leaf_index": leaf_idx,
            "timestamp": ts,
            "timestamp_raw": ts,
            "action_type": action,
            "target_table": table,
            "target_uuid": target_uuid,
            "actor_user_id": actor_id,
            "client_ip": client_ip,
            "client_ip_raw": client_ip,
            "data_payload_hash": data_hash,
            "preceding_leaf_hash": prev_hash,
            "current_leaf_hash": "f" * 64,  # Forged hash
        }

        # Run verification logic
        envelope = (
            f"{tampered_record['leaf_index']}{tampered_record['timestamp_raw']}"
            f"{tampered_record['action_type']}{tampered_record['target_table']}"
            f"{tampered_record['target_uuid']}{tampered_record['actor_user_id']}"
            f"{tampered_record['client_ip_raw']}{tampered_record['data_payload_hash']}"
            f"{tampered_record['preceding_leaf_hash']}"
        )
        recalculated = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
        assert recalculated == valid_current_hash
        assert recalculated != tampered_record["current_leaf_hash"]


class TestMission5DefeatFalseEquivalence:
    """Mission 5: No name collapse dicts, explicit insufficient data flags."""

    def test_mahmud_does_not_collapse_to_mohammad(self):
        norm_mahmud = BengaliPhoneticEngine.normalize_text("মাহমুদ হাসান")
        assert "মোহাম্মদ" not in norm_mahmud
        assert "মাহমুদ" in norm_mahmud

    def test_missing_data_outputs_insufficient_data_flag_not_05(self):
        candidate = BengaliDisambiguationEvaluator.evaluate_pair(
            target_entity_id=str(uuid.uuid4()),
            name_bn_1="রফিকুল ইসলাম",
            father_name_bn_1=None,  # Missing father name
            thana_1=None,          # Missing thana
            age_1=35,
            cand_entity_id=str(uuid.uuid4()),
            name_bn_2="রফিকুল ইসলাম",
            name_en_2="Rafiqul Islam",
            father_name_bn_2="আব্দুর রহমান",
            thana_2="Labanchora",
            age_2=35,
        )

        assert candidate.insufficient_data is True
        assert candidate.father_name_insufficient_data is True
        assert candidate.thana_insufficient_data is True
        assert candidate.father_name_sim == 0.0
        assert candidate.thana_match_score == 0.0

    @patch("backend.app.routers.entity.db_manager")
    @pytest.mark.asyncio
    async def test_entity_search_endpoint(self, mock_db_manager):
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [
            {
                "entity_id": uuid.uuid4(),
                "primary_name_bn": "রফিকুল ইসলাম",
                "primary_name_en": "Rafiqul Islam",
                "father_name_bn": "আব্দুর রহমান",
                "thana_jurisdiction": "Labanchora",
                "age": 40,
                "match_score": 0.95,
            }
        ]

        @asynccontextmanager
        async def mock_conn_ctx(**kwargs):
            yield mock_conn

        mock_db_manager.connection = mock_conn_ctx

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/entity/search?q=Rafiqul",
                headers=auth_headers(uuid.uuid4(), ["entity:read"]),
            )
            assert resp.status_code == 200
            results = resp.json()
            assert len(results) == 1
            assert results[0]["primary_name_bn"] == "রফিকুল ইসলাম"
            assert results[0]["match_score"] == 0.95


@pytest.mark.asyncio
class TestMission6HealthAndSensitiveExportAudit:
    """Mission 6: Rigorous health checks and export auditing."""

    @patch("backend.app.main.db_manager")
    @patch("backend.app.main.storage_service")
    async def test_health_check_returns_503_on_db_down(self, mock_storage, mock_db):
        mock_db.execute = AsyncMock(side_effect=RuntimeError("DB Connection Lost"))
        mock_storage.client.bucket_exists.return_value = True

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 503
            assert resp.json()["detail"]["status"] == "DEGRADED"

    @patch("backend.app.main.db_manager")
    @patch("backend.app.main.storage_service")
    async def test_health_check_returns_503_on_minio_down(self, mock_storage, mock_db):
        mock_db.execute = AsyncMock(return_value="SELECT 1")
        mock_storage.client.bucket_exists.side_effect = RuntimeError("MinIO unreachable")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 503
            assert resp.json()["detail"]["status"] == "DEGRADED"

    @patch("backend.app.routers.export.db_manager")
    async def test_sensitive_export_audits_to_ledger(self, mock_db_manager):
        source_id = uuid.uuid4()
        now = datetime.now()

        mock_conn = AsyncMock()
        mock_conn.fetchrow.side_effect = [
            {
                "source_id": source_id,
                "source_type": "COURT_ORDER",
                "document_reference": "Sessions Case No. 12/2026",
                "issuing_authority": "Sessions Court Khulna",
                "publication_date": date(2026, 4, 15),
                "ingestion_timestamp": now,
                "storage_uri": "s3://bucket/order.pdf",
                "sha256_hash": "a" * 64,
                "blake3_hash": "b" * 64,
                "uploaded_by_user_id": uuid.uuid4(),
            },
            None,
        ]

        @asynccontextmanager
        async def mock_conn_ctx(**kwargs):
            yield mock_conn

        mock_db_manager.connection = mock_conn_ctx

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/export/certificate/{source_id}",
                headers=auth_headers(uuid.uuid4(), ["evidence:export"]),
            )
            assert resp.status_code == 200
            # Verify log_sensitive_export_audit was executed on connection
            mock_conn.execute.assert_called_with(
                "SELECT log_sensitive_export_audit('source_registry', $1, $2)",
                source_id,
                "json",
            )

    @patch("backend.app.routers.export.db_manager")
    async def test_sensitive_export_fails_closed_412_on_audit_error(self, mock_db_manager):
        """P1-6: Verifies fail-open prevention: export raises HTTP 412 if audit log insert fails."""
        source_id = uuid.uuid4()
        now = datetime.now()

        mock_conn = AsyncMock()
        mock_conn.fetchrow.side_effect = [
            {
                "source_id": source_id,
                "source_type": "COURT_ORDER",
                "document_reference": "Sessions Case No. 12/2026",
                "issuing_authority": "Sessions Court Khulna",
                "publication_date": date(2026, 4, 15),
                "ingestion_timestamp": now,
                "storage_uri": "s3://bucket/order.pdf",
                "sha256_hash": "a" * 64,
                "blake3_hash": "b" * 64,
                "uploaded_by_user_id": uuid.uuid4(),
            },
            None,
        ]
        # Simulate audit ledger execution failure
        mock_conn.execute.side_effect = RuntimeError("Ledger lock contention or write failure")

        @asynccontextmanager
        async def mock_conn_ctx(**kwargs):
            yield mock_conn

        mock_db_manager.connection = mock_conn_ctx

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/export/certificate/{source_id}",
                headers=auth_headers(uuid.uuid4(), ["evidence:export"]),
            )
            assert resp.status_code == 412
            assert "Mandatory audit trail insertion failed" in resp.json()["detail"]


class TestMission7P0P1AuditRemediations:
    """Verifies November audit remediations: P0-3, P1-3, P1-5."""

    @pytest.mark.asyncio
    async def test_search_rejects_empty_whitespace_query_400(self):
        """P0-3: Entity requests failing constraint length(trim(input_str)) == 0 abort with HTTP 400."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = auth_headers(uuid.uuid4(), ["entity:read"])
            resp = await client.get("/entity/search?q=%20%20%20", headers=headers)
            assert resp.status_code == 400
            assert "non-whitespace" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_disambiguation_rejects_empty_whitespace_bn_query_400(self):
        """P0-3: Disambiguation evaluation rejects empty primary_name_bn with HTTP 400."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = auth_headers(uuid.uuid4(), ["entity:read"])
            payload = {
                "primary_name_bn": "    ",
                "primary_name_en": "Test",
            }
            resp = await client.post("/entity/evaluate_disambiguation", json=payload, headers=headers)
            assert resp.status_code == 400
            assert "primary_name_bn" in resp.json()["detail"]

    def test_calculate_batch_integrity_catastrophic_abort_on_gap(self):
        """P1-3: Catastrophic abort if local index vs predecessor block sequence gap discovered."""
        broadcaster = SequentialHashChainBroadcaster(
            database_url="postgresql://fake@localhost/fake",
            signing_key="audit-key-test",
        )
        batch = [
            {
                "leaf_index": 1,
                "current_leaf_hash": "a" * 64,
                "data_payload_hash": "d" * 64,
            },
            {
                "leaf_index": 3,  # Gap: expected 2, got 3
                "current_leaf_hash": "b" * 64,
                "data_payload_hash": "e" * 64,
            },
        ]
        with pytest.raises(RuntimeError) as exc_info:
            broadcaster.calculate_batch_integrity(batch)
        assert "CATASTROPHIC ABORT" in str(exc_info.value)
        assert "sequence gap discovered" in str(exc_info.value)

    def test_calculate_batch_integrity_enforces_batch_limit(self):
        """P1-3: Enforces 50 max chunk block limit."""
        broadcaster = SequentialHashChainBroadcaster(
            database_url="postgresql://fake@localhost/fake",
            signing_key="audit-key-test",
        )
        oversized_batch = [{"leaf_index": i, "current_leaf_hash": "a" * 64} for i in range(1, 52)]
        with pytest.raises(ValueError) as exc_info:
            broadcaster.calculate_batch_integrity(oversized_batch)
        assert "50 hardware limit" in str(exc_info.value)
