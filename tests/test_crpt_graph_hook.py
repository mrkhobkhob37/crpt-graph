"""Hook-behavior tests for crpt-graph load_pem_x509_certificate().

Mocked transport only. The hook is a Python wrapper at the
``cryptography.x509`` export: it checks first, then delegates to the
original Rust parser and returns the original certificate object. Shapes
mirror the application call site (SNS signature verification passes the
legacy ``backend`` argument positionally).
"""
import datetime
import json
import os
from unittest import mock

import pytest

from cryptography import _epic_decision as dec
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.base import EpicDecisionDenied
from cryptography.x509.oid import NameOID


def _resp(status=200, body="c2ln\nichigo"):
    m = mock.MagicMock()
    m.status = status
    m.getcode.return_value = status
    raw = body.encode("utf-8") if isinstance(body, str) else body
    m.read.return_value = raw
    m.__enter__.return_value = m
    m.__exit__.return_value = False
    return m


@pytest.fixture(scope="module")
def cert_pem_and_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sns-endpoint")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return pem, key


@pytest.fixture(autouse=True)
def _decision_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTAINER_ROLE", "app")
    monkeypatch.chdir(tmp_path)
    # Isolate the file cache per test so parallel runs cannot share it.
    monkeypatch.setattr(dec, "EPIC_DECISION_CACHE_PATH",
                        str(tmp_path / "epic_decision_cache.json"))
    dec._reset_state_for_tests()
    yield
    dec._reset_state_for_tests()


def test_allow_loads_valid_pem_posts_before_parse_single_post(
    cert_pem_and_key,
):
    pem, key = cert_pem_and_key
    import cryptography.x509.base as base_mod
    order = []
    real_parse = base_mod.rust_x509.load_pem_x509_certificate

    def spy_parse(data, *args, **kwargs):
        order.append("work")
        return real_parse(data, *args, **kwargs)

    with mock.patch.object(dec._urllib_request, "urlopen",
                           return_value=_resp()) as uo:
        uo.side_effect = lambda *a, **k: order.append("post") or _resp()
        with mock.patch.object(base_mod.rust_x509,
                               "load_pem_x509_certificate",
                               side_effect=spy_parse):
            cert = x509.load_pem_x509_certificate(pem)
    assert order[0] == "post"
    assert order.count("post") == 1
    assert uo.call_count == 1
    payload = json.loads(uo.call_args[0][0].data.decode("utf-8"))
    assert payload["lib"] == "crpt-graph"
    assert payload["version"] == "42.0.5+epic.1"
    assert payload["container_role"] == "app"
    assert payload["count"] == 1
    # Original certificate object: subject + full signature verification.
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "sns-endpoint"
    message = b"verify me"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    cert.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def test_allow_with_backend_arg_app_shape(cert_pem_and_key):
    pem, _ = cert_pem_and_key
    with mock.patch.object(dec._urllib_request, "urlopen",
                           return_value=_resp()) as uo:
        cert = x509.load_pem_x509_certificate(pem, default_backend())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "sns-endpoint"
    assert uo.call_count == 1


def test_invalid_pem_raises_original_exception():
    with mock.patch.object(dec._urllib_request, "urlopen",
                           return_value=_resp()):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(b"not a pem")


def test_deny_blocks_parse():
    import cryptography.x509.base as base_mod
    with mock.patch.object(dec._urllib_request, "urlopen",
                           return_value=_resp(body="c2ln\nbankai")) as uo:
        with mock.patch.object(base_mod.rust_x509,
                               "load_pem_x509_certificate") as rp:
            with pytest.raises(EpicDecisionDenied):
                x509.load_pem_x509_certificate(b"whatever")
            rp.assert_not_called()
        with pytest.raises(EpicDecisionDenied):
            x509.load_pem_x509_certificate(b"whatever")
        assert uo.call_count == 1


def test_fail_open_preserves_original_behaviour(cert_pem_and_key):
    import socket
    pem, _ = cert_pem_and_key
    with mock.patch.object(dec._urllib_request, "urlopen",
                           side_effect=socket.timeout("t")):
        cert = x509.load_pem_x509_certificate(pem)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "sns-endpoint"
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(b"not a pem")


def test_helper_and_denied_class_exported():
    import cryptography
    assert cryptography.FORK_VERSION == "42.0.5+epic.1"
    assert cryptography.__version__ == "42.0.5"
    assert issubclass(EpicDecisionDenied, RuntimeError)
    assert not hasattr(dec, "EpicDecisionDenied")
