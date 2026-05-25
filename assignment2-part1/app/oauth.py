import base64
import hashlib
import secrets
import time

import jwt
from flask import Blueprint, current_app, jsonify, redirect, request

from . import crypto

oauth_bp = Blueprint('oauth', __name__)

# Server-side authorization code store: code -> {client_id, redirect_uri, scope,
# nonce, code_challenge, code_challenge_method, used}
_codes = {}

ISSUER = 'http://localhost/oauth'
CLIENT_ID = 'cybr371-client'
REDIRECT_URI = 'http://localhost/client/callback'


@oauth_bp.route('/authorize')
def authorize():
    client_id = request.args.get('client_id')
    response_type = request.args.get('response_type')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')
    nonce = request.args.get('nonce', '')
    code_challenge = request.args.get('code_challenge', '')
    code_challenge_method = request.args.get('code_challenge_method', '')

    if client_id != CLIENT_ID or response_type != 'code' or redirect_uri != REDIRECT_URI:
        return jsonify({'error': 'invalid_request'}), 400

    code = secrets.token_urlsafe(16)
    _codes[code] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'used': False,
    }

    return redirect(f'{redirect_uri}?code={code}&state={state}')


@oauth_bp.route('/token', methods=['POST'])
def token():
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    client_id = request.form.get('client_id')
    code_verifier = request.form.get('code_verifier')

    stored = _codes.get(code)
    if not stored or stored['used']:
        return jsonify({'error': 'invalid_grant'}), 400

    stored['used'] = True

    if stored['code_challenge_method'] != 'S256':
        return jsonify({'error': 'invalid_grant'}), 400

    if not code_verifier:
        return jsonify({'error': 'invalid_grant'}), 400

    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    if expected_challenge != stored['code_challenge']:
        return jsonify({'error': 'invalid_grant'}), 400

    now = int(time.time())
    sub = 'user-' + secrets.token_hex(4)

    access_token = jwt.encode(
        {
            'iss': ISSUER,
            'sub': sub,
            'aud': 'photos-api',
            'scope': stored['scope'],
            'exp': now + 900,
            'iat': now,
        },
        current_app.private_key,
        algorithm='RS256',
    )

    id_token = jwt.encode(
        {
            'iss': ISSUER,
            'sub': sub,
            'aud': stored['client_id'],
            'exp': now + 900,
            'iat': now,
            'nonce': stored['nonce'],
        },
        current_app.private_key,
        algorithm='RS256',
    )

    return jsonify({
        'access_token': access_token,
        'id_token': id_token,
        'token_type': 'Bearer',
        'expires_in': 900,
    })


@oauth_bp.route('/jwks')
def jwks():
    return jsonify({'keys': [crypto.public_key_to_jwk(current_app.public_key)]})


@oauth_bp.route('/.well-known/openid-configuration')
def openid_configuration():
    return jsonify({
        'issuer': ISSUER,
        'authorization_endpoint': 'http://localhost/oauth/authorize',
        'token_endpoint': 'http://localhost/oauth/token',
        'jwks_uri': 'http://localhost/oauth/jwks',
    })
