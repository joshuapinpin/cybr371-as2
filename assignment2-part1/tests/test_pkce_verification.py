"""Task 6 — PKCE code verifier."""
from urllib.parse import urlparse

import pytest


def _start_flow(client):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302
    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302
    cb_parsed = urlparse(auth_resp.headers['Location'])
    return cb_parsed.path + '?' + cb_parsed.query


def test_missing_verifier_causes_400(client):
    callback_path = _start_flow(client)
    with client.session_transaction() as sess:
        sess.pop('code_verifier', None)
    resp = client.get(callback_path)
    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_wrong_verifier_causes_400(client):
    callback_path = _start_flow(client)
    with client.session_transaction() as sess:
        sess['code_verifier'] = 'completely-wrong-verifier-xyz-000'
    resp = client.get(callback_path)
    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_verifier_from_different_flow_rejected(app, client):
    from unittest.mock import MagicMock, patch

    client.get('/client/login')
    with client.session_transaction() as sess:
        verifier_a = sess.get('code_verifier')
    assert verifier_a

    client_b = app.test_client()

    def fake_post(url, data=None, **kwargs):
        from urllib.parse import urlparse as _up
        idp_c = app.test_client()
        r = idp_c.post(_up(url).path, data=data)
        m = MagicMock()
        m.status_code = r.status_code
        m.json.return_value = r.get_json()
        return m

    with patch('app.client.requests.post', side_effect=fake_post):
        login_b = client_b.get('/client/login')
        assert login_b.status_code == 302
        parsed_b = urlparse(login_b.headers['Location'])
        auth_b = client_b.get(parsed_b.path + '?' + parsed_b.query)
        assert auth_b.status_code == 302
        cb_parsed_b = urlparse(auth_b.headers['Location'])
        callback_b = cb_parsed_b.path + '?' + cb_parsed_b.query

        with client_b.session_transaction() as sess_b:
            sess_b['code_verifier'] = verifier_a

        resp = client_b.get(callback_b)

    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


@pytest.mark.parametrize('run_number', [1, 2, 3])
def test_correct_verifier_accepted(valid_flow, run_number):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
