"""Task 8 — Open redirect."""
import secrets
from urllib.parse import urlparse

import pytest


def _flow_with_next(client, next_url):
    login_resp = client.get(f'/client/login?next={next_url}')
    assert login_resp.status_code == 302

    parsed = urlparse(login_resp.headers['Location'])
    auth_resp = client.get(parsed.path + '?' + parsed.query)
    assert auth_resp.status_code == 302

    cb_parsed = urlparse(auth_resp.headers['Location'])
    return client.get(cb_parsed.path + '?' + cb_parsed.query)


def _is_external(location):
    if not location:
        return False
    parsed = urlparse(location)
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)


@pytest.mark.parametrize('_', range(3))
def test_external_url_rejected(client, _):
    next_url = f'https://{secrets.token_hex(6)}.example.com/steal'
    resp = _flow_with_next(client, next_url)
    if resp.status_code == 302 and _is_external(resp.headers.get('Location', '')):
        pytest.fail(f"redirected to external URL: {resp.headers.get('Location')}")


def test_http_external_rejected(client):
    resp = _flow_with_next(client, 'http://evil.com/phish')
    if resp.status_code == 302 and _is_external(resp.headers.get('Location', '')):
        pytest.fail(f"redirected to external URL: {resp.headers.get('Location')}")


def test_protocol_relative_rejected(client):
    resp = _flow_with_next(client, '//evil.com/steal')
    location = resp.headers.get('Location', '')
    if resp.status_code == 302 and location.startswith('//'):
        pytest.fail(f"redirected to protocol-relative URL: {location}")


def test_relative_path_accepted(client):
    resp = _flow_with_next(client, '/profile')
    if not (resp.status_code == 302 and resp.headers.get('Location', '').endswith('/profile')):
        pytest.fail(f"got {resp.status_code}, expected 302 to /profile")


def test_no_next_still_succeeds(client, valid_flow):
    resp = valid_flow()
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
