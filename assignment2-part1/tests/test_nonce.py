"""Task 3 — Nonce binding."""
import secrets
from unittest.mock import patch
from urllib.parse import urlparse

import pytest


def _flow_with_forged_id_token(client, id_token):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302
    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302

    with patch('app.client.requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'id_token': id_token,
            'access_token': 'dummy',
        }
        cb_parsed = urlparse(auth_resp.headers['Location'])
        return client.get(cb_parsed.path + '?' + cb_parsed.query)


@pytest.mark.parametrize('_', range(3))
def test_wrong_nonce_rejected(client, oauth_token_factory, _):
    wrong_nonce = secrets.token_urlsafe(16)
    bad_token = oauth_token_factory(aud='cybr371-client', nonce=wrong_nonce)
    resp = _flow_with_forged_id_token(client, bad_token)
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_missing_nonce_rejected(client, oauth_token_factory):
    bad_token = oauth_token_factory(aud='cybr371-client', include_nonce=False)
    resp = _flow_with_forged_id_token(client, bad_token)
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_replayed_nonce_rejected(client, oauth_token_factory, valid_flow):
    resp1 = valid_flow()
    assert resp1.status_code == 200

    with client.session_transaction() as sess:
        old_nonce = sess.get('nonce')
    assert old_nonce

    bad_token = oauth_token_factory(aud='cybr371-client', nonce=old_nonce)
    resp2 = _flow_with_forged_id_token(client, bad_token)
    if resp2.status_code != 401:
        pytest.fail(f"got {resp2.status_code}, expected 401")


def test_correct_nonce_accepted(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
