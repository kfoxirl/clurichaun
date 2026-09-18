"""Cloud object-storage sources: S3 and GCS.

A bucket is just another stream of bytes, so each object flows through the same
ingestion + detection pipeline as a file (archives, source maps and binaries in a
bucket work exactly as on disk). The cloud SDKs are optional (`[cloud]` extra):
the client is injected, so tests exercise the walk and scan with a fake and never
touch a real bucket or need credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Protocol, Tuple

from .models import ScanStats

MAX_OBJECT_BYTES = 64 * 1024 * 1024


class ObjectClient(Protocol):
    """Minimal object-store interface both S3 and GCS adapters satisfy."""

    def list_objects(self, prefix: str) -> Iterator[Tuple[str, int]]: ...
    def get_object(self, key: str) -> bytes: ...


@dataclass
class CloudSource:
    client: ObjectClient
    prefix: str = ""
    max_object_bytes: int = MAX_OBJECT_BYTES
    scheme: str = "s3"
    bucket: str = ""

    def blobs(self, stats: ScanStats) -> Iterator[Tuple[str, bytes]]:
        try:
            listing = list(self.client.list_objects(self.prefix))
        except Exception as exc:  # noqa: BLE001 - SDK errors vary widely
            stats.errors.append(f"{self._root()}: list failed: {exc}")
            return
        for key, size in listing:
            if size > self.max_object_bytes:
                stats.errors.append(f"{self._uri(key)}: skipped, {size} bytes over limit")
                continue
            try:
                data = self.client.get_object(key)
            except Exception as exc:  # noqa: BLE001
                stats.errors.append(f"{self._uri(key)}: get failed: {exc}")
                continue
            if data:
                yield self._uri(key), data

    def _root(self) -> str:
        return f"{self.scheme}://{self.bucket}"

    def _uri(self, key: str) -> str:
        return f"{self._root()}/{key}"


# --------------------------------------------------------------------------- #
# S3
# --------------------------------------------------------------------------- #


@dataclass
class S3Client:
    """boto3-backed S3 client (lazy import; the [cloud] extra)."""

    bucket: str
    _s3: object = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        import boto3  # optional dependency

        self._s3 = boto3.client("s3")

    def list_objects(self, prefix: str) -> Iterator[Tuple[str, int]]:
        paginator = self._s3.get_paginator("list_objects_v2")  # type: ignore[union-attr]
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                yield obj["Key"], obj.get("Size", 0)

    def get_object(self, key: str) -> bytes:
        resp = self._s3.get_object(Bucket=self.bucket, Key=key)  # type: ignore[union-attr]
        return resp["Body"].read()


# --------------------------------------------------------------------------- #
# GCS
# --------------------------------------------------------------------------- #


@dataclass
class GCSClient:
    """google-cloud-storage client (lazy import; the [cloud] extra)."""

    bucket: str
    _bucket: object = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        from google.cloud import storage  # optional dependency

        self._bucket = storage.Client().bucket(self.bucket)

    def list_objects(self, prefix: str) -> Iterator[Tuple[str, int]]:
        for blob in self._bucket.list_blobs(prefix=prefix):  # type: ignore[union-attr]
            yield blob.name, (blob.size or 0)

    def get_object(self, key: str) -> bytes:
        return self._bucket.blob(key).download_as_bytes()  # type: ignore[union-attr]


def parse_bucket_uri(uri: str) -> Tuple[str, str, str]:
    """``s3://bucket/prefix`` -> (scheme, bucket, prefix)."""
    for scheme in ("s3", "gs", "gcs"):
        marker = f"{scheme}://"
        if uri.startswith(marker):
            rest = uri[len(marker):]
            bucket, _, prefix = rest.partition("/")
            return ("gs" if scheme in ("gs", "gcs") else "s3"), bucket, prefix
    raise ValueError(f"not a bucket URI (expected s3:// or gs://): {uri}")


def make_source(uri: str) -> CloudSource:
    scheme, bucket, prefix = parse_bucket_uri(uri)
    if scheme == "gs":
        return CloudSource(GCSClient(bucket), prefix=prefix, scheme="gs", bucket=bucket)
    return CloudSource(S3Client(bucket), prefix=prefix, scheme="s3", bucket=bucket)
