import json
from flask import request, jsonify
from functools import wraps
from jose import jwt
from urllib.request import urlopen
from os import getenv
# Load variables from .env file.
from dotenv import load_dotenv
load_dotenv()

AUTH0_DOMAIN = getenv('AUTH0_DOMAIN')
# Load the json keys from website (For once only.)
jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
json_web_keyset = json.loads(jsonurl.read())

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header"""

    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)
    
    # Get the token part from Authorization header
    return parts[1]

def decode_and_verify(jwks, token, key_id):
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == key_id:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if not rsa_key: 
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to find the appropriate key.'
        }, 400)
    
    decoded_payload = None
    try:
        decoded_payload = jwt.decode(
            token,
            rsa_key,
            algorithms=['RS256'],
            audience=getenv('AUTH0_API_AUDIENCE'),
            issuer='https://' + AUTH0_DOMAIN + '/'
        )
    except jwt.ExpiredSignatureError:
        raise AuthError({
            'code': 'token_expired',
            'description': 'Token expired.'
        }, 401)

    except jwt.JWTClaimsError:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Incorrect claims. Please, check the audience and issuer.'
        }, 401)
    except Exception:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to parse authentication token.'
        }, 400)

    # Payload decoded in to Dictionary
    return decoded_payload

def requires_auth(f):
    global json_web_keyset
    """
        Determines if the Access Token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Get the token from headers
            jwt_token = get_token_auth_header()
            unverified_header = jwt.get_unverified_header(jwt_token)
        
            # Decode the token and verify the headers
            payload = decode_and_verify(json_web_keyset, jwt_token, key_id=unverified_header['kid'])
            return f(payload, *args, **kwargs)
        except AuthError as e: 
            return jsonify(e.error), e.status_code

    return decorated