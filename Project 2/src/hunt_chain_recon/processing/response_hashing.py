"""Deterministic HTTP response hashing for Hunt_Chain Project 2.

This module provides response-body hashing used by Project 2 to identify
identical HTTP responses.

V1 uses SHA-256 exclusively.

The hasher:
- accepts raw response bytes,
- produces a lowercase hexadecimal SHA-256 digest,
- does not decode or transform response bodies,
- does not perform network activity,
- does not make vulnerability determinations.

Response hashing is an observation/processing operation. A matching
response hash does not by itself mean that two endpoints are identical
in every meaningful way, nor does it indicate a vulnerability.
"""

from __future__ import annotations

import hashlib
from typing import SupportsBytes


class ResponseHashingError(ValueError):
    """Raised when an invalid HTTP response body is supplied."""


class SHA256ResponseHasher:
    """Calculate SHA-256 hashes for raw HTTP response bodies."""

    algorithm = "sha256"

    def hash_body(
        self,
        body: bytes | bytearray | memoryview,
    ) -> str:
        """Return the SHA-256 hexadecimal digest of a response body.

        The response body is hashed exactly as supplied. No text decoding,
        normalization, whitespace removal, decompression, or other
        transformation is performed here.

        Parameters
        ----------
        body:
            Raw HTTP response body bytes.

        Returns
        -------
        str
            Lowercase hexadecimal SHA-256 digest.

        Raises
        ------
        ResponseHashingError
            If the supplied value is not a supported byte container.
        """
        if not isinstance(
            body,
            (bytes, bytearray, memoryview),
        ):
            raise ResponseHashingError(
                "HTTP response body must be bytes."
            )

        try:
            digest = hashlib.sha256(body)
        except (TypeError, ValueError) as exc:
            raise ResponseHashingError(
                "Unable to calculate SHA-256 response hash."
            ) from exc

        return digest.hexdigest()


__all__ = [
    "ResponseHashingError",
    "SHA256ResponseHasher",
]