from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Optional
from minio import Minio
from minio.error import S3Error
from minio.retention import Retention
from minio.commonconfig import COMPLIANCE

from backend.app.config import settings


class MinioWORMStorage:
    """Manages S3 Object Lock (WORM - Write Once, Read Many) compliance storage."""

    @staticmethod
    def _normalize_object_name(object_name: str) -> str:
        normalized = str(object_name).replace("\\", "/").strip()
        parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
        if not parts:
            raise ValueError("Object name must include at least one non-empty path segment.")
        sanitized = "/".join(parts)
        if sanitized.startswith("/"):
            sanitized = sanitized.lstrip("/")
        return sanitized

    def __init__(self) -> None:
        self.client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )
        self.bucket_name = settings.MINIO_EVIDENCE_BUCKET
        self.retention_years = settings.MINIO_RETENTION_YEARS

    def ensure_bucket_exists(self) -> None:
        """
        Ensures the WORM bucket exists with Object Locking enabled.
        Note: Object Lock must be configured at bucket creation time.
        """
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(
                    bucket_name=self.bucket_name,
                    object_lock=True,
                )
        except S3Error as e:
            # If already created or requires specific privilege, log
            pass

    def upload_evidence(
        self,
        object_name: str,
        data_stream: BinaryIO,
        length: int,
        content_type: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Uploads evidence blob into S3 bucket with COMPLIANCE retention lock.
        Once locked in COMPLIANCE mode, no user (including root) can overwrite
        or delete the object until the retention period expires.
        """
        safe_object_name = self._normalize_object_name(object_name)
        self.ensure_bucket_exists()

        retain_until = datetime.now(timezone.utc) + timedelta(days=365 * self.retention_years)
        retention = Retention(
            mode=COMPLIANCE,
            retain_until_date=retain_until,
        )

        data_stream.seek(0)
        self.client.put_object(
            bucket_name=self.bucket_name,
            object_name=safe_object_name,
            data=data_stream,
            length=length,
            content_type=content_type,
            metadata=metadata or {},
            retention=retention,
        )

        return f"s3://{self.bucket_name}/{safe_object_name}"

    def get_object(self, object_name: str) -> BinaryIO:
        """Retrieves read stream for a stored evidence object."""
        response = self.client.get_object(self.bucket_name, object_name)
        return response

    def attempt_delete_object(self, object_name: str) -> bool:
        """
        Attempts to delete an object. Under WORM compliance mode,
        this will raise an S3Error indicating ObjectLockConfiguration or AccessDenied.
        """
        self.client.remove_object(self.bucket_name, object_name)
        return True


storage_service = MinioWORMStorage()
