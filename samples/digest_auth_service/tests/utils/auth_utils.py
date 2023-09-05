import re
import hashlib
import time
# parsing regex
reg = re.compile(r'(\w+)[:=][\s"]?([^",]+)"?')

# construct challenge structer
def construct_challenge(auth_directives: dict, nonce=''):
    return {'realm': auth_directives["realm"],
            'nonce': auth_directives['nonce'] if len(nonce) == 0 else nonce,
            'algorithm': auth_directives["algorithm"],
            'qop': "auth"
            }


def parse_directives(authentication_header: str):
    return dict(reg.findall(authentication_header))

# checks if mandatory directives are in WWW-Authenticate header
def auth_directives_assert(auth_directives: dir):
    assert 'realm' in auth_directives
    assert 'nonce' in auth_directives
    assert 'algorithm' in auth_directives
    assert 'qop' in auth_directives

# construct authorization header sent from client
def build_digest_header(method, uri, chal, username, password):
        realm = chal['realm']
        nonce = chal['nonce']
        qop = chal.get('qop')
        algorithm = chal.get('algorithm')
        opaque = chal.get('opaque')
        hash_utf8 = None

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        if _algorithm == 'MD5':
            def md5_utf8(x):
                x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA256':
            def sha256_utf8(x):
                x = x.encode('utf-8')
                return hashlib.sha256(x).hexdigest()
            hash_utf8 = sha256_utf8
        elif _algorithm == 'SHA512':
            def sha512_utf8(x):
                x = x.encode('utf-8')
                return hashlib.sha512(x).hexdigest()
            hash_utf8 = sha512_utf8
        else:
            return None

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        A1 = '%s:%s:%s' % (username, realm, password)
        A2 = '%s:%s' % (method, uri)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        nonce_count = 1
        ncvalue = '%08x' % nonce_count
        s = str(nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')

        cnonce = (hashlib.sha1(s).hexdigest()[:16])

        noncebit = "%s:%s:%s:%s:%s" % (
                nonce, ncvalue, cnonce, 'auth', HA2
        )
        response_digest = KD(HA1, noncebit)
            
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (username, realm, nonce, uri, response_digest)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)
