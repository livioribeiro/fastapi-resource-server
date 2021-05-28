from fastapi import Depends, FastAPI, Security
from pydantic import BaseModel

from fastapi_resource_server import GrantType, JwtDecodeOptions, OidcResourceServer

app = FastAPI()

allowed_grant_types = [GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT]
decode_options = JwtDecodeOptions(verify_aud=False)

auth_scheme = OidcResourceServer(
    "http://localhost:8888/auth/realms/master",
    scheme_name="Keycloak",
    allowed_grant_types=allowed_grant_types,
    jwt_decode_options=decode_options,
)


class User(BaseModel):
    username: str
    given_name: str
    family_name: str
    email: str


def get_current_user(claims: dict = Security(auth_scheme)):
    claims.update(username=claims["preferred_username"])
    user = User.parse_obj(claims)
    return user


@app.get("/users/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
