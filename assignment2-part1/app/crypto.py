import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def init_app(app):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    app.private_key = private_key
    app.public_key = private_key.public_key()


def public_key_to_jwk(public_key):
    nums = public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big')
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big')
    return {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'n': base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode(),
        'e': base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode(),
    }
