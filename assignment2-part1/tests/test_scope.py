"""Task 5 — Scope enforcement."""
import secrets
import pytest


@pytest.mark.parametrize('_', range(3))
def test_random_scope_rejected(client, oauth_token_factory, _):
    scope = secrets.token_urlsafe(8)
    token = oauth_token_factory(scope=scope, aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


@pytest.mark.parametrize('scope', ['', 'calendar.read', 'photos.write'])
def test_wrong_scope_rejected(client, oauth_token_factory, scope):
    token = oauth_token_factory(scope=scope, aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


def test_no_scope_rejected(client, oauth_token_factory):
    token = oauth_token_factory(scope=None, aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


def test_write_scope_only_rejected(client, oauth_token_factory):
    token = oauth_token_factory(scope='photos.write', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


def test_scope_substring_prefix_rejected(client, oauth_token_factory):
    token = oauth_token_factory(scope='xphotos.read', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


def test_scope_substring_suffix_rejected(client, oauth_token_factory):
    token = oauth_token_factory(scope='photos.read.admin', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 403:
        pytest.fail(f"got {resp.status_code}, expected 403")


def test_correct_scope_accepted(client, oauth_token_factory):
    token = oauth_token_factory(scope='photos.read', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")


def test_multiple_scopes_including_correct_accepted(client, oauth_token_factory):
    token = oauth_token_factory(scope='photos.read calendar.read', aud='photos-api', include_nonce=False)
    resp = client.get('/api/photos', headers={'Authorization': f'Bearer {token}'})
    if resp.status_code != 200:
        pytest.fail(f"got {resp.status_code}, expected 200")
