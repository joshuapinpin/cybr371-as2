"""Task 7 — PKCE S256 method."""
import base64
import hashlib
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest


def test_plain_method_causes_400(client):
    with patch('app.client.PKCE_METHOD', 'plain'):
        login_resp = client.get('/client/login')
        assert login_resp.status_code == 302
        parsed = urlparse(login_resp.headers['Location'])
        auth_resp = client.get(parsed.path + '?' + parsed.query)
        assert auth_resp.status_code == 302
        cb_parsed = urlparse(auth_resp.headers['Location'])
        resp = client.get(cb_parsed.path + '?' + cb_parsed.query)

    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_s256_accepted_after_fix(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")


def test_challenge_is_hash_of_verifier(client):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302

    params = parse_qs(urlparse(login_resp.headers['Location']).query)
    challenge = params.get('code_challenge', [None])[0]
    method = params.get('code_challenge_method', [None])[0]

    with client.session_transaction() as sess:
        verifier = sess.get('code_verifier')
    assert verifier

    if method != 'S256':
        pytest.fail(f"code_challenge_method='{method}', expected 'S256'")

    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode()

    if challenge != expected:
        pytest.fail(f"code_challenge does not equal BASE64URL(SHA256(verifier))")

    if challenge == verifier:
        pytest.fail("code_challenge equals code_verifier — plain method detected")
