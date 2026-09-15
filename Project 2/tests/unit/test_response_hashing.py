"""Tests for deterministic HTTP response hashing."""

from __future__ import annotations

import hashlib

import pytest

from hunt_chain_recon.processing.response_hashing import (
    ResponseHashingError,
    SHA256ResponseHasher,
)


def test_sha256_hash_is_deterministic() -> None:
    """The same response body always produces the same hash."""
    hasher = SHA256ResponseHasher()

    first = hasher.hash_body(b"hello world")
    second = hasher.hash_body(b"hello world")

    assert first == second


def test_sha256_hash_matches_standard_library() -> None:
    """The implementation matches Python's SHA-256 implementation."""
    body = b"hunt_chain_response"

    hasher = SHA256ResponseHasher()

    assert hasher.hash_body(body) == hashlib.sha256(body).hexdigest()


def test_sha256_hash_has_expected_length() -> None:
    """SHA-256 output is represented as a 64-character hexadecimal string."""
    hasher = SHA256ResponseHasher()

    result = hasher.hash_body(b"example")

    assert len(result) == 64
    assert result == result.lower()


def test_empty_body_is_hashed() -> None:
    """An empty response body is still hashed."""
    hasher = SHA256ResponseHasher()

    assert hasher.hash_body(b"") == hashlib.sha256(b"").hexdigest()


def test_binary_body_is_hashed_without_decoding() -> None:
    """Binary response bodies are hashed directly as bytes."""
    body = bytes(range(256))

    hasher = SHA256ResponseHasher()

    assert hasher.hash_body(body) == hashlib.sha256(body).hexdigest()


def test_hash_changes_when_body_changes() -> None:
    """Different response bodies produce different hashes."""
    hasher = SHA256ResponseHasher()

    first = hasher.hash_body(b"response-one")
    second = hasher.hash_body(b"response-two")

    assert first != second


def test_hasher_does_not_modify_input() -> None:
    """Hashing does not mutate a mutable byte buffer."""
    body = bytearray(b"immutable-for-hashing")
    original = bytes(body)

    hasher = SHA256ResponseHasher()
    hasher.hash_body(body)

    assert bytes(body) == original


def test_non_bytes_input_is_rejected() -> None:
    """Response hashing requires raw response bytes."""
    hasher = SHA256ResponseHasher()

    with pytest.raises(ResponseHashingError):
        hasher.hash_body("hello")


def test_none_input_is_rejected() -> None:
    """None is not a valid HTTP response body."""
    hasher = SHA256ResponseHasher()

    with pytest.raises(ResponseHashingError):
        hasher.hash_body(None)


def test_hash_algorithm_is_explicit() -> None:
    """The V1 hasher exposes SHA-256 as its algorithm."""
    hasher = SHA256ResponseHasher()

    assert hasher.algorithm == "sha256"


def test_hash_is_lowercase_hexadecimal() -> None:
    """The returned digest contains only lowercase hexadecimal characters."""
    hasher = SHA256ResponseHasher()

    result = hasher.hash_body(b"test")

    assert all(
        character in "0123456789abcdef"
        for character in result
    )