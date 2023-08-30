from http import HTTPStatus

from endpoints import follow_user
from endpoints import get_profile
from endpoints import register_user
from endpoints import unfollow_user
from models import Profile
from models import User
from utils import get_user_token
from validators import validate_profile


async def test_unfollow_user_unauthorized(service_client):
    user = User()
    response = await unfollow_user(service_client, user, None)
    assert response.status == HTTPStatus.UNAUTHORIZED


async def test_unfollow_unknown_user(service_client):
    user = User(bio=None, image=None)
    response = await register_user(service_client, user)
    assert response.status == HTTPStatus.OK

    user.username = 'some-user'
    response = await unfollow_user(
        service_client, user, get_user_token(response),
    )
    assert response.status == HTTPStatus.NOT_FOUND


async def test_unfollow_user(service_client):
    user = User(bio=None, image=None)

    response = await register_user(service_client, user)
    assert response.status == HTTPStatus.OK

    user_token = get_user_token(response)

    followed_user = User(bio=None, image=None)
    response = await register_user(service_client, followed_user)
    assert response.status == HTTPStatus.OK

    response = await follow_user(service_client, followed_user, user_token)
    assert response.status == HTTPStatus.OK

    response = await unfollow_user(service_client, followed_user, user_token)
    assert response.status == HTTPStatus.OK

    followed_profile = Profile(followed_user)
    assert validate_profile(followed_profile, response)

    response = await get_profile(service_client, followed_user, user_token)
    assert response.status == HTTPStatus.OK
    assert validate_profile(followed_profile, response)
