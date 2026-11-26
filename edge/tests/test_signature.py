from __future__ import annotations

import hashlib

import pytest

from hispanshield_edge.client import (
    InvalidBundleError,
    build_signature_message,
    canonical_json,
    compute_signature,
    sign_config_bundle,
    verify_signed_bundle,
)

SECRET = "s3cr3t-key"
TIMESTAMP = "1700000000"
METHOD = "POST"
PATH = "/api/v1/edge/gateways/11111111-1111-1111-1111-111111111111/heartbeat"
BODY = b'{"version":"0.1.0"}'
EXPECTED_BODY_SHA256 = "701d838178929148f2eb418c3c97c99636c033fc2efa6874d65299f6df4929d2"
EXPECTED_SIGNATURE = "fa0357bf29d6931e0b7fa54ebe474aad3d3c4c5ad6995668111735ccddacdb5f"
BUNDLE = {"bundle": {"gateway_id": "x", "config": {"batch_size": 10}}}
EXPECTED_BUNDLE_SIGNATURE = "934b7eb9d12d87c48aa8cff741c1ae1dc8469ee24413b47e8938a0c74d5efab1"


def test_signature_vector_matches_independent_rsa_vector():
    # Vector generated independently with openssl-equivalent HMAC primitives.
    assert hashlib.sha256(BODY).hexdigest() == EXPECTED_BODY_SHA256
    assert build_signature_message(TIMESTAMP, METHOD, PATH, BODY) == (
        f"{TIMESTAMP}\n{METHOD}\n{PATH}\n{EXPECTED_BODY_SHA256}".encode()
    )
    assert compute_signature(SECRET, TIMESTAMP, METHOD, PATH, BODY) == EXPECTED_SIGNATURE


def test_signature_binds_method_path_and_body():
    baseline = compute_signature(SECRET, TIMESTAMP, METHOD, PATH, BODY)
    assert compute_signature(SECRET, TIMESTAMP, "GET", PATH, BODY) != baseline
    assert compute_signature(SECRET, TIMESTAMP, METHOD, f"{PATH}/x", BODY) != baseline
    assert compute_signature(SECRET, TIMESTAMP, METHOD, PATH, b'{"version":"0.1.1"}') != baseline
    assert compute_signature("other-secret", TIMESTAMP, METHOD, PATH, BODY) != baseline
    assert compute_signature(SECRET, "1700000001", METHOD, PATH, BODY) != baseline


def test_signature_is_lowercase_hex_of_64_chars():
    signature = compute_signature(SECRET, TIMESTAMP, METHOD, PATH, BODY)
    assert len(signature) == 64
    assert signature == signature.lower()
    int(signature, 16)


def test_config_bundle_signature_uses_canonical_json():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert sign_config_bundle(SECRET, BUNDLE["bundle"]) == EXPECTED_BUNDLE_SIGNATURE


def test_verify_bundle_accepts_valid_document():
    bundle = {"gateway_id": "gw-1", "fingerprint": "fp-1", "config": {"batch_size": 5}}
    document = {
        "bundle": bundle,
        "signature": sign_config_bundle(SECRET, bundle),
        "algorithm": "HMAC-SHA256",
    }
    verified = verify_signed_bundle(SECRET, document, expected_gateway_id="gw-1", expected_fingerprint="fp-1")
    assert verified == bundle


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document["bundle"]["config"].update({"batch_size": 500}),
        lambda document: document.update({"signature": "0" * 64}),
        lambda document: document.pop("signature"),
        lambda document: document.update({"algorithm": "none"}),
        lambda document: document.update({"bundle": "not-an-object"}),
    ],
)
def test_verify_bundle_rejects_tampering(mutate):
    bundle = {"gateway_id": "gw-1", "fingerprint": "fp-1", "config": {"batch_size": 5}}
    document = {
        "bundle": bundle,
        "signature": sign_config_bundle(SECRET, bundle),
        "algorithm": "HMAC-SHA256",
    }
    mutate(document)
    with pytest.raises(InvalidBundleError):
        verify_signed_bundle(SECRET, document)


def test_verify_bundle_rejects_other_gateway_or_fingerprint():
    bundle = {"gateway_id": "gw-1", "fingerprint": "fp-1", "config": {}}
    document = {
        "bundle": bundle,
        "signature": sign_config_bundle(SECRET, bundle),
        "algorithm": "HMAC-SHA256",
    }
    with pytest.raises(InvalidBundleError):
        verify_signed_bundle(SECRET, document, expected_gateway_id="gw-2")
    with pytest.raises(InvalidBundleError):
        verify_signed_bundle(SECRET, document, expected_fingerprint="fp-2")
