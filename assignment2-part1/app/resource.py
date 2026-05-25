import jwt
from flask import Blueprint, current_app, jsonify, request

resource_bp = Blueprint('resource', __name__)

ISSUER = 'http://localhost/oauth'
AUDIENCE = 'photos-api'
REQUIRED_SCOPE = 'photos.read'

PHOTOS = [
    {'id': 1, 'title': 'Sunset', 'url': '/photos/sunset.jpg'},
    {'id': 2, 'title': 'Mountains', 'url': '/photos/mountains.jpg'},
    {'id': 3, 'title': 'Ocean', 'url': '/photos/ocean.jpg'},
]


@resource_bp.route('/photos')
def photos():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'missing_token'}), 401

    token = auth_header[len('Bearer '):]

    try:
        payload = jwt.decode(
            token,
            current_app.public_key,
            algorithms=['RS256'],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={'require': ['exp', 'aud', 'iss']},
        )
    except jwt.PyJWTError:
        return jsonify({'error': 'invalid_token'}), 401

    return jsonify({'photos': PHOTOS})
