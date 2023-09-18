# type: ignore
import re

from requests.auth import HTTPDigestAuth


# parsing regex
REG = re.compile(r'(\w+)[:=][\s"]?([^",]+)"?')


# construct challenge structer
def construct_challenge(fields: dict, nonce=''):
    return {
        'realm': fields['realm'],
        'nonce': fields['nonce'] if len(nonce) == 0 else nonce,
        'algorithm': fields['algorithm'],
        'qop': 'auth',
    }


# construct authorization header sent from client
def construct_header(username: str, password: str, challenge: dict, uri: str):
    digest_auth = HTTPDigestAuth(username, password)
    digest_auth.init_per_thread_state()
    # pylint: disable=protected-access
    digest_auth._thread_local.chal = challenge
    return digest_auth.build_digest_header('GET', uri)


def parse_fields(authentication_header: str):
    return dict(REG.findall(authentication_header))


# checks if the fields are present in WWW-Authenticate header
def auth_header_fields_asserts(fields: dict):
    assert 'realm' in fields
    assert 'nonce' in fields
    assert 'algorithm' in fields
    assert 'qop' in fields
    assert 'charset' in fields
    assert 'userhash' in fields


# checks if the fields are present in Authentication-Info header
def auth_info_header_fields_asserts(fields: dict):
    assert 'nextnonce' in fields
    assert 'qop' in fields
    assert 'cnonce' in fields
    assert 'nc' in fields
