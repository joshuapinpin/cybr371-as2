import base64
import hashlib
import secrets
from urllib.parse import urlencode

import jwt
import requests
from flask import Blueprint, current_app, jsonify, redirect, request, session

client_bp = Blueprint('client', __name__)

CLIENT_ID = 'cybr371-client'
REDIRECT_URI = 'http://localhost/client/callback'
TOKEN_ENDPOINT = 'http://localhost/oauth/token'
AUTHORIZE_ENDPOINT = '/oauth/authorize'

PKCE_METHOD = 'S256'


@client_bp.route('/login')
def login():
    next_url = request.args.get('next')
    if next_url:
        session['next'] = next_url

    code_verifier = secrets.token_urlsafe(32)

    if PKCE_METHOD == 'S256':
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    else:
        code_challenge = code_verifier

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    session['state'] = state
    session['nonce'] = nonce
    session['code_verifier'] = code_verifier

    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid photos.read',
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': PKCE_METHOD,
    }
    return redirect(AUTHORIZE_ENDPOINT + '?' + urlencode(params))


@client_bp.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return jsonify({'error': 'missing_code'}), 400

    # Validate state parameter (CSRF protection)
    stored_state = session.get('state')
    if not state or state != stored_state:
        return jsonify({'error': 'invalid_state'}), 400

    code_verifier = session.get('code_verifier')
    token_response = requests.post(TOKEN_ENDPOINT, data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier,  # Include PKCE verifier
    })

    if token_response.status_code != 200:
        return jsonify({'error': 'token_exchange_failed'}), token_response.status_code

    tokens = token_response.json()
    id_token_str = tokens.get('id_token')
    access_token = tokens.get('access_token')

    if not id_token_str:
        return jsonify({'error': 'missing_id_token'}), 400

    try:
        # 1: Hardcode algorithm (never read from token header)
        # 2: Validate audience matches client_id
        # 3: Validate nonce to prevent replay attacks
        id_token = jwt.decode(
            id_token_str,
            current_app.public_key,
            algorithms=['RS256'],
            audience=CLIENT_ID,
            options={'require': ['nonce']},
        )

        # Verify nonce matches the one stored in session
        stored_nonce = session.get('nonce')
        if id_token.get('nonce') != stored_nonce:
            return jsonify({'error': 'invalid_nonce'}), 401
    except jwt.PyJWTError:
        return jsonify({'error': 'invalid_id_token'}), 401

    session['access_token'] = access_token

    # Validate redirect URL is safe (same-origin only)
    next_url = session.pop('next', None)
    if next_url:
        # Only allow relative paths starting with / but not //
        if not next_url.startswith('/') or next_url.startswith('//'):
            return jsonify({'error': 'invalid_redirect'}), 400
        return redirect(next_url)

    return jsonify({'status': 'login successful', 'sub': id_token.get('sub')}), 200
