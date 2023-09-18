# /// [Functional test]
import pytest

import auth_utils

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_authenticate_base(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Authentication-Info' in response.headers

    fields = auth_utils.parse_fields(response.headers['Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)


# /// [Functional test]


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_authenticate_base_unregisted_user(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header(
        'unregistred_username', 'pswd', challenge, '/v1/hello'
    )

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 403


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_postgres_wrong_data(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header(
        'username', 'wrong-password', challenge, '/v1/hello'
    )

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401
    assert 'WWW-Authenticate' in response.headers


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_repeated_auth(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    fields_info = auth_utils.parse_fields(response.headers['Authentication-Info'])

    challenge = auth_utils.construct_challenge(
        fields, fields_info['nextnonce'],
    )
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Authentication-Info' in response.headers

    fields = auth_utils.parse_fields(response.headers['Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_same_nonce_repeated_use(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    fields_info = auth_utils.parse_fields(response.headers['Authentication-Info'])

    challenge = auth_utils.construct_challenge(
        fields, fields_info['nextnonce'],
    )
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401
    assert 'WWW-Authenticate' in response.headers


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_expiring_nonce(service_client, mocked_time):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    very_long_waiting_ms = 1500
    mocked_time.sleep(very_long_waiting_ms)

    fields_info = auth_utils.parse_fields(response.headers['Authentication-Info'])

    challenge = auth_utils.construct_challenge(
        fields, fields_info['nextnonce'],
    )
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Authentication-Info' in response.headers

    fields = auth_utils.parse_fields(response.headers['Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_aliving_nonce_after_half_ttl(service_client, mocked_time):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    short_waiting_ms = 500
    mocked_time.sleep(short_waiting_ms)

    fields_info = auth_utils.parse_fields(response.headers['Authentication-Info'])

    challenge = auth_utils.construct_challenge(
        fields, fields_info['nextnonce'],
    )
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200
    assert 'Authentication-Info' in response.headers

    fields = auth_utils.parse_fields(response.headers['Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)


@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_repeated_auth_ignore_nextnonce(service_client):
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])
    auth_utils.auth_header_fields_asserts(fields)

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    response = await service_client.get('/v1/hello')
    assert response.status == 401

    fields = auth_utils.parse_fields(response.headers['WWW-Authenticate'])

    challenge = auth_utils.construct_challenge(fields)
    auth_header = auth_utils.construct_header('username', 'pswd', challenge, '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200

    fields = auth_utils.parse_fields(response.headers['Authentication-Info'])
    auth_utils.auth_info_header_fields_asserts(fields)
