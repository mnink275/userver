# type: ignore
import re

from requests.auth import HTTPDigestAuth


# parsing regex
REG = re.compile(r'(\w+)[:=][\s"]?([^",]+)"?')


# construct challenge structer
def construct_challenge(auth_directives: dict, nonce=''):
    return {
        'realm': auth_directives['realm'],
        'nonce': auth_directives['nonce'] if len(nonce) == 0 else nonce,
        'algorithm': auth_directives['algorithm'],
        'qop': 'auth',
    }


# construct authorization header sent from client
def construct_header(username: str, password: str, challenge: dict, uri: str):
    digest_auth = HTTPDigestAuth(username, password)
    digest_auth.init_per_thread_state()
    # pylint: disable=protected-access
    digest_auth._thread_local.chal = challenge
    return digest_auth.build_digest_header('GET', uri)


def parse_directives(authentication_header: str):
    return dict(REG.findall(authentication_header))


# checks if the fields are present in WWW-Authenticate header
def auth_fields_assert(auth_directives: dict):
    assert 'realm' in auth_directives
    assert 'nonce' in auth_directives
    assert 'algorithm' in auth_directives
    assert 'qop' in auth_directives
    assert 'charset' in auth_directives
    assert 'userhash' in auth_directives


# checks if the fields are present in Authentication-Info header
def auth_info_fields_assert(auth_directives: dict):
    assert 'nextnonce' in auth_directives
    assert 'qop' in auth_directives
    assert 'cnonce' in auth_directives
    assert 'nc' in auth_directives
