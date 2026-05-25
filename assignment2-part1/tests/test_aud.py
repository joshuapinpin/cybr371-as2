"""Task 2 — Audience validation."""
import secrets
from unittest.mock import patch
from urllib.parse import urlparse

import pytest


def _flow_with_forged_id_token(client, oauth_token_factory, **kwargs):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302

    with client.session_transaction() as sess:
        session_nonce = sess.get('nonce', 'fallback-nonce')

    bad_token = oauth_token_factory(nonce=session_nonce, **kwargs)

    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302

    callback_location = auth_resp.headers['Location']
    with patch('app.client.requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'id_token': bad_token,
            'access_token': 'dummy',
        }
        cb_parsed = urlparse(callback_location)
        return client.get(cb_parsed.path + '?' + cb_parsed.query)


@pytest.mark.parametrize('_', range(3))
def test_wrong_aud_rejected(client, oauth_token_factory, _):
    wrong_aud = secrets.token_urlsafe(8)
    resp = _flow_with_forged_id_token(client, oauth_token_factory, aud=wrong_aud)
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_missing_aud_rejected(client, oauth_token_factory):
    resp = _flow_with_forged_id_token(client, oauth_token_factory, aud=None)
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_resource_server_aud_in_id_token_rejected(client, oauth_token_factory):
    resp = _flow_with_forged_id_token(client, oauth_token_factory, aud='photos-api')
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_correct_aud_accepted(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
