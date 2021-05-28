# FastAPI Resource Server

Build an OIDC resource server using FastAPI.

Your aplication receives the claims decoded from the access token.

# Usage

Run keycloak on port 8888:

```sh
docker container run --name auth-server -d -p 8888:8080 \
    -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin \
    jboss/keycloak:latest
```

Install dependencies

```sh
pip install fastapi fastapi_resource_server uvicorn
```

Create the main.py module

```python
from fastapi import Depends, FastAPI, Security
from pydantic import BaseModel

from fastapi_resource_server import JwtDecodeOptions, OidcResourceServer

app = FastAPI()

decode_options = JwtDecodeOptions(verify_aud=False)

auth_scheme = OidcResourceServer(
    "http://localhost:8888/auth/realms/master",
    scheme_name="Keycloak",
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
```

Run the application

```sh
uvicorn main:app
```
