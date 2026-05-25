"""Task 4 — State / CSRF protection."""
import secrets
from urllib.parse import parse_qs, urlencode, urlparse

import pytest


def _flow_with_state(client, override_state):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302

    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302

    cb_parsed = urlparse(auth_resp.headers['Location'])
    params = parse_qs(cb_parsed.query)
    params['state'] = [override_state]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return client.get(cb_parsed.path + '?' + new_query)


@pytest.mark.parametrize('_', range(3))
def test_wrong_state_rejected(client, _):
    wrong_state = secrets.token_urlsafe(16)
    resp = _flow_with_state(client, wrong_state)
    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_missing_state_rejected(client):
    login_resp = client.get('/client/login')
    assert login_resp.status_code == 302
    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302

    cb_parsed = urlparse(auth_resp.headers['Location'])
    params = parse_qs(cb_parsed.query)
    params.pop('state', None)
    new_query = urlencode({k: v[0] for k, v in params.items()})
    resp = client.get(cb_parsed.path + '?' + new_query)
    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_state_from_different_session_rejected(app, client):
    client2 = app.test_client()
    login2 = client2.get('/client/login')
    assert login2.status_code == 302
    with client2.session_transaction() as sess2:
        foreign_state = sess2.get('state')
    assert foreign_state

    resp = _flow_with_state(client, foreign_state)
    if resp.status_code not in (400, 401):
        pytest.fail(f"got {resp.status_code}, expected 400 or 401")


def test_correct_state_accepted(valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
