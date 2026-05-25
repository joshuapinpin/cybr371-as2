# Library Reference

---

## PyJWT

```python
import jwt
```

### Decoding a token

```python
payload = jwt.decode(
    token,          # the JWT string
    key,            # public key (RSA) or secret (HMAC)
    algorithms=[],  # list of accepted algorithms, e.g. ["RS256"]
    audience="",    # expected aud value — PyJWT checks this automatically
    issuer="",      # expected iss value — PyJWT checks this automatically
    options={},     # extra options (see below)
)
```

`jwt.decode` raises `jwt.PyJWTError` (or a subclass) if the signature is invalid, the token is expired, the issuer does not match, or any required claim is missing. Wrap it in `try/except jwt.PyJWTError`.

### Common `options`

| Key | Type | Effect |
|-----|------|--------|
| `"verify_aud"` | bool | Set `False` to skip PyJWT's built-in aud check so you can check it manually |
| `"require"` | list | Claim names that must be present, e.g. `["exp", "aud", "iss"]` |

### Reading the token header without verifying

```python
header = jwt.get_unverified_header(token)
# header is a dict, e.g. {"alg": "RS256", "typ": "JWT"}
```

This does not verify the signature. Use it for inspection only — never for making security decisions.

### Encoding (signing) a token

```python
token = jwt.encode(payload_dict, private_key, algorithm="RS256")
```

---

## Flask — session

`session` is a signed cookie dict. Values survive across requests for the same browser session.

```python
from flask import session

session['key'] = 'value'   # store
value = session.get('key') # read (returns None if missing)
session.pop('key', None)   # remove and return
```

---

## Flask — request

```python
from flask import request

value = request.args.get('param')        # query string: ?param=value
value = request.args.get('param', '')    # with default
header = request.headers.get('Authorization', '')
```

---

## Flask — redirect and response

```python
from flask import redirect, jsonify

return redirect('/some/path')            # 302 by default
return jsonify({'error': 'reason'}), 401
```

---

## hashlib + base64 (PKCE S256)

```python
import hashlib, base64, secrets

# Generate verifier
code_verifier = secrets.token_urlsafe(32)

# Derive challenge
digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
```

`rstrip(b'=')` removes base64 padding — RFC 7636 requires unpadded base64url.

---

## URL validation

```python
# Accept only same-origin relative paths
def is_safe_redirect(url):
    return url.startswith('/') and not url.startswith('//')
```

`//evil.com` starts with `/` but is protocol-relative — browsers resolve it as an external URL.
