# /// [Functional test]
import pytest
from auth_utils import *

USERVER_CONFIG_HOOKS = ['proxy_config']

@pytest.fixture(scope='session')
def proxy_config():
    def _patch_config(config_yaml, config_vars):
        components = config_yaml['components_manager']['components']
        components['auth-digest-checker-settings']['is-proxy'] = true
    return _patch_config

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_authenticate_base_proxy(proxy_config, service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    assert 'WWW-Authenticate' in response.headers
    authentication_header = response.headers["Proxy-Authenticate"]
    auth_directives = parse_directives(authentication_header)

    assert 'realm' in auth_directives
    assert 'nonce' in auth_directives
    assert 'algorithm' in auth_directives
    assert 'qop' in auth_directives

    challenge = construct_challenge(auth_directives)
    auth_header = construct_header("username", "pswd", challenge)

    response = await service_client.get(
        '/v1/hello', headers={'Proxy-Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Proxy-Authentication-Info' in response.headers
# /// [Functional test]