from fastapi_resource_server import GrantType


def test_grant_type():
    assert GrantType.AUTHORIZATION_CODE.value == "authorization_code"
