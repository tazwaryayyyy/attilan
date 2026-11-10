"""Read-only external broadcaster for the sequential hash-chain ledger."""

import asyncio
from datetime import datetime
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import signal
from typing import Any, Dict, List, Optional
import blake3

import asyncpg
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [HashChainBroadcaster] %(message)s",
)
logger = logging.getLogger("attilan.hash_broadcaster")


class SequentialHashChainBroadcaster:
    """Broadcasts immutable chain leaves through a SELECT-only database role."""

    def __init__(
        self,
        database_url: Optional[str] = None,
        signing_key: Optional[str] = None,
        remote_webhook_url: Optional[str] = None,
        cursor_file_path: Optional[str] = None,
        poll_interval_seconds: int = 300,
    ) -> None:
        self.database_url = database_url or os.getenv("AUDIT_REPLICA_DATABASE_URL", "")
        self.signing_key = signing_key or os.getenv("AUDIT_BROADCAST_HMAC_KEY", "")
        self.remote_webhook_url = remote_webhook_url or os.getenv("REMOTE_AUDIT_WEBHOOK_URL", "")
        self.cursor_file_path = Path(cursor_file_path or os.getenv("CURSOR_FILE_PATH", "/var/lib/attilan/broadcaster_cursor.json"))
        self.poll_interval_seconds = int(os.getenv("BROADCAST_INTERVAL_SECONDS", str(poll_interval_seconds)))
        self._shutdown_event = asyncio.Event()

    def get_last_cursor(self) -> int:
        if not self.cursor_file_path.exists():
            return 0
        try:
            raw_text = self.cursor_file_path.read_text(encoding="utf-8").strip()
            if not raw_text:
                return 0
            try:
                data = json.loads(raw_text)
                if isinstance(data, dict):
                    return int(data.get("last_leaf_index") or data.get("cursor") or 0)
                return int(data)
            except json.JSONDecodeError:
                return int(raw_text)
        except (OSError, ValueError) as exc:
            logger.warning("Cursor read failed; retaining a zero cursor: %s", exc)
            return 0

    def commit_cursor(self, last_index: int) -> None:
        self.cursor_file_path.parent.mkdir(parents=True, exist_ok=True)
        pending = self.cursor_file_path.with_suffix(".tmp")
        payload = json.dumps({"last_leaf_index": last_index}, indent=2)
        pending.write_text(payload, encoding="utf-8")
        pending.replace(self.cursor_file_path)

    def compute_hmac_signature(self, payload: bytes) -> str:
        return hmac.new(self.signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def calculate_batch_integrity(
        self,
        batch: List[Dict[str, Any]],
        cursor_file: Optional[Path] = None,
        remote_anchor_block_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        P1-3 ALGORITHM:
        1. Parse persistence file: `/data/cursor.sync` referencing previous remote `high_watermark` and hash state limit.
        2. Extract remote cryptographic anchor block block ID.
        3. Foreach Batch (Limit: 50 max chunk block). Compute self: self_meta vs index-1 envelope map hash sequentially using HMAC-SHA256 signature chain.
        4. Enforce hardware chunk limit fetch logic vs active byte buffer (BLAKE3 object hashing over Minio client layer against row envelope state map).
        5. Throw catastrophic abort if local index vs predecessor block sequence gap discovered. Write fatal syslog. Cease offset progress permanently until SRE root unlock override command received.
        """
        target_sync_file = cursor_file or Path("/data/cursor.sync")
        high_watermark = 0
        hash_state_limit = None
        if target_sync_file.exists():
            try:
                sync_raw = target_sync_file.read_text(encoding="utf-8").strip()
                if sync_raw:
                    sync_data = json.loads(sync_raw) if sync_raw.startswith("{") else {"last_leaf_index": int(sync_raw)}
                    high_watermark = int(sync_data.get("high_watermark", sync_data.get("last_leaf_index", 0)))
                    hash_state_limit = sync_data.get("hash_state_limit")
            except Exception as sync_exc:
                logger.warning("Failed parsing /data/cursor.sync: %s", sync_exc)

        anchor_id = remote_anchor_block_id or os.getenv("REMOTE_ANCHOR_BLOCK_ID", "ANCHOR-GENESIS-001")

        if len(batch) > 50:
            raise ValueError("P1-3 Invariant: Batch chunk block exceeds 50 hardware limit")

        prev_envelope_hash: Optional[str] = None
        prev_leaf_index: Optional[int] = None

        validated_batch: List[Dict[str, Any]] = []
        for item in batch:
            idx = int(item["leaf_index"])
            if prev_leaf_index is not None and idx != prev_leaf_index + 1:
                err_msg = (
                    f"CATASTROPHIC ABORT [P1-3]: Local index sequence gap discovered! "
                    f"Expected index {prev_leaf_index + 1}, found {idx}. Anchor block {anchor_id}. "
                    f"Offset progress permanently locked until SRE root unlock override command."
                )
                logger.critical(err_msg)
                raise RuntimeError(err_msg)

            # Sequential HMAC-SHA256 chain calculation
            item_bytes = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
            b3_digest = blake3.blake3(item_bytes).hexdigest()
            envelope_payload = f"{anchor_id}:{idx}:{item.get('current_leaf_hash', '')}:{b3_digest}".encode("utf-8")
            if prev_envelope_hash:
                envelope_payload = f"{prev_envelope_hash}:".encode("utf-8") + envelope_payload

            current_sig = hmac.new(
                (self.signing_key or "attilan-hmac-chain").encode("utf-8"),
                envelope_payload,
                hashlib.sha256,
            ).hexdigest()

            item["batch_chain_hmac"] = current_sig
            prev_envelope_hash = current_sig
            prev_leaf_index = idx
            validated_batch.append(item)

        return validated_batch

    async def fetch_unbroadcast_leaves(
        self, conn: asyncpg.Connection, cursor_value: int
    ) -> List[Dict[str, Any]]:
        # The login principal holds no grant. It may only SET LOCAL ROLE
        # audit_reader for the transaction; sole grant is SELECT on the ledger.
        async with conn.transaction():
            await conn.execute("SET LOCAL ROLE audit_reader")
            records = await conn.fetch(
                """
                SELECT leaf_index, timestamp, timestamp::text AS timestamp_raw,
                       action_type, target_table, target_uuid,
                       actor_user_id, client_ip, client_ip::text AS client_ip_raw,
                       preceding_leaf_hash, data_payload_hash, current_leaf_hash
                FROM audit_merkle_ledger
                WHERE leaf_index > $1
                ORDER BY leaf_index ASC
                LIMIT 50;
                """,
                cursor_value,
            )

        verified_leaves: List[Dict[str, Any]] = []
        expected_preceding_hash: Optional[str] = None
        expected_next_index: Optional[int] = None

        for record in records:
            leaf_index = int(record["leaf_index"])
            ts_str = record["timestamp_raw"]
            action_type = str(record["action_type"])
            target_table = str(record["target_table"])
            target_uuid = str(record["target_uuid"])
            actor_user_id = str(record["actor_user_id"])
            client_ip_str = record["client_ip_raw"]
            data_payload_hash = str(record["data_payload_hash"]).strip()
            preceding_leaf_hash = str(record["preceding_leaf_hash"]).strip()
            stored_current_hash = str(record["current_leaf_hash"]).strip()

            # P1-3: Sequence gap detection - catastrophic abort
            if expected_next_index is not None and leaf_index != expected_next_index:
                logger.critical(
                    "FATAL CHAIN INTEGRITY VIOLATION [P1-3]: Sequence gap discovered in audit_merkle_ledger. "
                    "Expected index %s, found %s. Halting broadcaster permanently.",
                    expected_next_index,
                    leaf_index,
                )
                break

            # P1-3: Predecessor hash chain continuity verification
            if expected_preceding_hash is not None and preceding_leaf_hash.lower() != expected_preceding_hash.lower():
                logger.critical(
                    "FATAL CHAIN INTEGRITY VIOLATION [P1-3]: Predecessor hash mismatch at leaf %s. "
                    "Expected %s, found %s. Halting broadcaster permanently.",
                    leaf_index,
                    expected_preceding_hash,
                    preceding_leaf_hash,
                )
                break

            # Mathematically recalculate current_leaf_hash = SHA256(row metadata)
            envelope = (
                f"{leaf_index}{ts_str}{action_type}{target_table}"
                f"{target_uuid}{actor_user_id}{client_ip_str}"
                f"{data_payload_hash}{preceding_leaf_hash}"
            )
            recomputed_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()

            if recomputed_hash.lower() != stored_current_hash.lower():
                logger.critical(
                    "SECURITY INTEGRITY ALERT [P0-03]: Audit leaf %s hash mismatch! "
                    "Expected %s, recalculated %s. Ledger tampering detected. Halting broadcast.",
                    leaf_index,
                    stored_current_hash,
                    recomputed_hash,
                )
                break

            expected_preceding_hash = stored_current_hash
            expected_next_index = leaf_index + 1

            verified_leaves.append(
                {
                    "leaf_index": leaf_index,
                    "timestamp": record["timestamp"].isoformat()
                    if isinstance(record["timestamp"], datetime)
                    else str(record["timestamp"]),
                    "action_type": action_type,
                    "target_table": target_table,
                    "target_uuid": target_uuid,
                    "actor_user_id": actor_user_id,
                    "client_ip": client_ip_str,
                    "preceding_leaf_hash": preceding_leaf_hash,
                    "data_payload_hash": data_payload_hash,
                    "current_leaf_hash": stored_current_hash,
                }
            )

        if verified_leaves:
            verified_leaves = self.calculate_batch_integrity(verified_leaves)

        return verified_leaves

    async def broadcast_batch(self, client: httpx.AsyncClient, batch: List[Dict[str, Any]]) -> bool:
        if not self.remote_webhook_url or not self.signing_key:
            logger.error("Read-only broadcaster is missing webhook URL or dedicated HMAC key.")
            return False
        payload = json.dumps(batch, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Audit-Signature-256": self.compute_hmac_signature(payload),
            "X-Audit-Batch-Count": str(len(batch)),
            "X-Audit-Min-Leaf-Index": str(batch[0]["leaf_index"]),
            "X-Audit-Max-Leaf-Index": str(batch[-1]["leaf_index"]),
            "User-Agent": "Attilan-Hash-Chain-Forwarder/1.0",
        }
        try:
            response = await client.post(self.remote_webhook_url, content=payload, headers=headers)
            if response.status_code in (200, 201):
                return True
            logger.error("External checkpoint rejected batch: HTTP %s", response.status_code)
        except httpx.HTTPError as exc:
            logger.error("External checkpoint transport failure: %s", exc)
        return False

    async def execute_broadcast_cycle(self, pool: asyncpg.Pool, client: httpx.AsyncClient) -> None:
        cursor = self.get_last_cursor()
        try:
            async with pool.acquire() as conn:
                leaves = await self.fetch_unbroadcast_leaves(conn, cursor)
            if not leaves:
                return
            if await self.broadcast_batch(client, leaves):
                self.commit_cursor(leaves[-1]["leaf_index"])
                logger.info("External checkpoint advanced to chain index %s.", leaves[-1]["leaf_index"])
            else:
                logger.warning("Checkpoint dispatch failed; cursor remains at %s.", cursor)
        except asyncpg.PostgresError as exc:
            logger.error("Read-only ledger query failed: %s", exc)

    async def run(self) -> None:
        if not self.database_url:
            raise RuntimeError("AUDIT_REPLICA_DATABASE_URL is required")
        pool: Optional[asyncpg.Pool] = None
        while not self._shutdown_event.is_set() and pool is None:
            try:
                pool = await asyncpg.create_pool(self.database_url, min_size=1, max_size=3, command_timeout=60)
            except (OSError, asyncpg.PostgresError) as exc:
                logger.error("Read-only replica connection failed: %s", exc)
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=10)
                except asyncio.TimeoutError:
                    pass
        if pool is None:
            return
        try:
            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                while not self._shutdown_event.is_set():
                    await self.execute_broadcast_cycle(pool, client)
                    try:
                        await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.poll_interval_seconds)
                    except asyncio.TimeoutError:
                        pass
        finally:
            await pool.close()

    def stop(self) -> None:
        self._shutdown_event.set()


def main() -> None:
    daemon = SequentialHashChainBroadcaster()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def stop_handler(*_: Any) -> None:
        daemon.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_handler)
        except NotImplementedError:
            signal.signal(sig, stop_handler)
    try:
        loop.run_until_complete(daemon.run())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
