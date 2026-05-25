"""Task 1 — Algorithm confusion."""
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
            'access_token': 'dummy-access-token',
        }
        cb_parsed = urlparse(callback_location)
        return client.get(cb_parsed.path + '?' + cb_parsed.query)


@pytest.mark.parametrize('sub,exp_offset', [
    ('attacker-alpha', 900),
    ('attacker-beta', 1800),
    ('victim-user-gamma', 300),
])
def test_alg_none_id_token_rejected(client, oauth_token_factory, sub, exp_offset):
    resp = _flow_with_forged_id_token(
        client, oauth_token_factory,
        alg='none', aud='cybr371-client', sub=sub, exp_offset=exp_offset,
    )
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


@pytest.mark.parametrize('sub,exp_offset', [
    ('attacker-alpha', 900),
    ('attacker-beta', 1800),
    ('victim-user-gamma', 300),
])
def test_alg_none_access_token_rejected(client, oauth_token_factory, sub, exp_offset):
    token = oauth_token_factory(
        alg='none', aud='photos-api', scope='photos.read',
        include_nonce=False, sub=sub, exp_offset=exp_offset,
    )
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


@pytest.mark.parametrize('sub,exp_offset', [
    ('attacker-alpha', 900),
    ('attacker-beta', 1800),
    ('victim-user-gamma', 300),
])
def test_alg_none_with_valid_claims_still_rejected(client, oauth_token_factory, sub, exp_offset):
    resp = _flow_with_forged_id_token(
        client, oauth_token_factory,
        alg='none', aud='cybr371-client', sub=sub, exp_offset=exp_offset,
    )
    if resp.status_code != 401:
        pytest.fail(f"got {resp.status_code}, expected 401")


def test_legitimate_rs256_still_accepted(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
