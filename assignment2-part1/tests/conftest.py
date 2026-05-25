import os
import time
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import jwt
import pytest

from app import create_app
from app import oauth as oauth_module


@pytest.fixture(scope='session')
def app():
    application = create_app(testing=True)
    return application


@pytest.fixture
def client(app):
    """Flask test client with requests.post patched to route through Flask test client."""
    oauth_module._codes.clear()

    test_client = app.test_client()

    def fake_requests_post(url, data=None, **kwargs):
        path = urlparse(url).path
        oauth_client = app.test_client()
        resp = oauth_client.post(path, data=data)
        mock_resp = MagicMock()
        mock_resp.status_code = resp.status_code
        mock_resp.json.return_value = resp.get_json()
        return mock_resp

    with patch('app.client.requests.post', side_effect=fake_requests_post):
        yield test_client

    oauth_module._codes.clear()


@pytest.fixture
def oauth_token_factory(app):
    """Mint forged JWTs directly, bypassing the OAuth server endpoints."""
    def factory(
        alg='RS256',
        aud='cybr371-client',
        iss='http://localhost/oauth',
        exp_offset=900,
        scope='photos.read',
        nonce='test-nonce',
        include_nonce=True,
        sub='test-user',
    ):
        now = int(time.time())
        payload = {
            'iss': iss,
            'sub': sub,
            'iat': now,
        }
        if aud is not None:
            payload['aud'] = aud
        if exp_offset is not None:
            payload['exp'] = now + exp_offset
        if scope is not None:
            payload['scope'] = scope
        if include_nonce:
            payload['nonce'] = nonce

        if alg == 'none':
            return jwt.encode(payload, '', algorithm='none')
        else:
            return jwt.encode(payload, app.private_key, algorithm=alg)

    return factory


@pytest.fixture
def valid_flow(client):
    """Run a complete login -> authorize -> callback flow. Returns the callback response."""
    def run():
        login_resp = client.get('/client/login')
        assert login_resp.status_code == 302, f"Login should redirect, got {login_resp.status_code}"

        oauth_location = login_resp.headers['Location']
        parsed = urlparse(oauth_location)
        oauth_path = parsed.path + ('?' + parsed.query if parsed.query else '')

        auth_resp = client.get(oauth_path)
        assert auth_resp.status_code == 302, f"OAuth authorize should redirect, got {auth_resp.status_code}"

        callback_location = auth_resp.headers['Location']
        parsed_cb = urlparse(callback_location)
        callback_path = parsed_cb.path + ('?' + parsed_cb.query if parsed_cb.query else '')

        return client.get(callback_path)

    return run


# Tests that pass on the unmodified starter code.
# If any of these fail, the student has introduced a regression.
_BASELINE_PASSING = {
    'tests/test_alg_none.py::test_alg_none_access_token_rejected[attacker-alpha-900]',
    'tests/test_alg_none.py::test_alg_none_access_token_rejected[attacker-beta-1800]',
    'tests/test_alg_none.py::test_alg_none_access_token_rejected[victim-user-gamma-300]',
    'tests/test_happy_path.py::test_correct_scope_grants_access',
    'tests/test_happy_path.py::test_valid_token_not_rejected_by_exp_check',
    'tests/test_pkce_plain.py::test_plain_method_causes_400',
    'tests/test_pkce_verification.py::test_missing_verifier_causes_400',
    'tests/test_pkce_verification.py::test_wrong_verifier_causes_400',
    'tests/test_pkce_verification.py::test_verifier_from_different_flow_rejected',
    'tests/test_scope.py::test_correct_scope_accepted',
    'tests/test_scope.py::test_multiple_scopes_including_correct_accepted',
}

_TASKS = {
    'test_happy_path':        ('Task 0 — Happy path',      'app/client.py + app/resource.py', 20),
    'test_alg_none':          ('Task 1 — alg:none',        'app/client.py',                   10),
    'test_aud':               ('Task 2 — Audience',        'app/client.py',                   10),
    'test_nonce':             ('Task 3 — Nonce',           'app/client.py',                   10),
    'test_state':             ('Task 4 — State',           'app/client.py',                   10),
    'test_scope':             ('Task 5 — Scope',           'app/resource.py',                 10),
    'test_pkce_verification': ('Task 6 — PKCE verifier',   'app/client.py',                   10),
    'test_pkce_plain':        ('Task 7 — PKCE S256',       'app/client.py',                   10),
    'test_redirect':          ('Task 8 — Open redirect',   'app/client.py',                   10),
}


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if getattr(config, '_tutor_results', False):
        return  # tutor_results.py handles output

    passed_ids = {r.nodeid for r in terminalreporter.stats.get('passed', [])}
    failed_ids = {r.nodeid for r in terminalreporter.stats.get('failed', [])}
    all_ids = passed_ids | failed_ids

    task_data = {}
    for nodeid in all_ids:
        key = os.path.basename(nodeid.split('::')[0]).replace('.py', '')
        if key not in _TASKS:
            continue
        task_data.setdefault(key, {'tests': []})
        passed = nodeid in passed_ids
        is_regression = nodeid in _BASELINE_PASSING
        test_name = nodeid.split('::')[1]
        task_data[key]['tests'].append((test_name, passed, is_regression))

    terminalreporter.write_sep('=', 'Results')

    sec_pass = sec_fail = reg_pass = reg_fail = 0

    for key, (label, target_file, _pts) in _TASKS.items():
        if key not in task_data:
            continue
        terminalreporter.write_line(f'  {label}  [{target_file}]')
        for test_name, passed, is_regression in task_data[key]['tests']:
            if passed:
                terminalreporter.write_line(f'    \033[32mPASS\033[0m  {test_name}')
            else:
                terminalreporter.write_line(f'    \033[31mFAIL\033[0m  {test_name}')
            if is_regression:
                if passed: reg_pass += 1
                else:       reg_fail += 1
            else:
                if passed: sec_pass += 1
                else:       sec_fail += 1

    terminalreporter.write_sep('-', '')
    terminalreporter.write_line(f'  Security tests:   {sec_pass} passed, {sec_fail} failed')
    terminalreporter.write_line(f'  Regression tests: {reg_pass} passed, {reg_fail} failed')
