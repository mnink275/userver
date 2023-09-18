import pytest

import auth_utils


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_authenticate_base_proxy(service_client):
    response = await service_client.get('/v1/hello-proxy')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['Proxy-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello-proxy')

    response = await service_client.get(
        '/v1/hello-proxy', headers={'Proxy-Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Proxy-Authentication-Info' in response.headers

    fields = auth_utils.parse_fields(response.headers['Proxy-Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_postgres_wrong_data_proxy(service_client):
    response = await service_client.get('/v1/hello-proxy')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['Proxy-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header(
        'username', 'wrong-password', challenge, '/v1/hello-proxy'
    )

    response = await service_client.get(
        '/v1/hello-proxy', headers={'Proxy-Authorization': auth_header},
    )
    assert response.status == 401
    assert 'Proxy-Authenticate' in response.headers
