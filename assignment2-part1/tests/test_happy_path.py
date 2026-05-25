"""Task 0 — Happy path."""
from urllib.parse import urlparse

import pytest


def test_full_flow_returns_200(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")


def test_access_token_grants_photos_access(client, valid_flow):
    resp = valid_flow()
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        access_token = sess.get('access_token')

    if not access_token:
        pytest.fail("no access_token in session after login")

    photos_resp = client.get('/api/photos', headers={'Authorization': f'Bearer {access_token}'})
    if photos_resp.status_code != 200:
        pytest.fail(f"GET /api/photos got {photos_resp.status_code}, expected 200")
    data = photos_resp.get_json()
    if 'photos' not in data:
        pytest.fail(f"response missing 'photos' key: {data}")


def test_multiple_flows_independent(app, client):
    """Two independent sessions must not interfere."""
    from unittest.mock import MagicMock, patch

    def run_flow(flask_client):
        def fake_post(url, data=None, **kwargs):
            from urllib.parse import urlparse as _up
            idp_c = app.test_client()
            r = idp_c.post(_up(url).path, data=data)
            m = MagicMock()
            m.status_code = r.status_code
            m.json.return_value = r.get_json()
            return m

        with patch('app.client.requests.post', side_effect=fake_post):
            login_resp = flask_client.get('/client/login')
            assert login_resp.status_code == 302
            parsed = urlparse(login_resp.headers['Location'])
            auth_resp = flask_client.get(parsed.path + '?' + parsed.query)
            assert auth_resp.status_code == 302
            cb_parsed = urlparse(auth_resp.headers['Location'])
            return flask_client.get(cb_parsed.path + '?' + cb_parsed.query)

    client2 = app.test_client()
    resp1 = run_flow(client)
    resp2 = run_flow(client2)

    if resp1.status_code != 200:
        pytest.fail(f"flow 1 got {resp1.status_code}, expected 200")
    if resp2.status_code != 200:
        pytest.fail(f"flow 2 got {resp2.status_code}, expected 200")


def test_valid_token_not_rejected_by_exp_check(client, oauth_token_factory):
    token = oauth_token_factory(exp_offset=300, aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")


def test_correct_scope_grants_access(client, oauth_token_factory):
    token = oauth_token_factory(scope='photos.read', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
