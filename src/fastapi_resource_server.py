import json
from enum import Enum
from typing import List, Optional
from urllib.request import urlopen

from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import (
    OAuthFlowAuthorizationCode,
    OAuthFlowClientCredentials,
    OAuthFlowImplicit,
    OAuthFlowPassword,
)
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security.oauth2 import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jose import jwt
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    IMPLICIT = "implicit"
    PASSWORD = "password"


def fetch_well_known(issuer: str) -> dict:
    url = f"{issuer}/.well-known/openid-configuration"
    with urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError("fail to fetch well-known")
        return json.load(response)


def fetch_jwks(well_known: dict) -> dict:
    url = well_known["jwks_uri"]
    with urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError("fail to fetch jwks")
        return json.load(response)


class JwtDecodeOptions(BaseModel):
    verify_signature: Optional[bool]
    verify_aud: Optional[bool]
    verify_iat: Optional[bool]
    verify_exp: Optional[bool]
    verify_nbf: Optional[bool]
    verify_iss: Optional[bool]
    verify_sub: Optional[bool]
    verify_jti: Optional[bool]
    verify_at_hash: Optional[bool]
    require_aud: Optional[bool]
    require_iat: Optional[bool]
    require_exp: Optional[bool]
    require_nbf: Optional[bool]
    require_iss: Optional[bool]
    require_sub: Optional[bool]
    require_jti: Optional[bool]
    require_at_hash: Optional[bool]
    leeway: Optional[int]


class OidcResourceServer(OAuth2):
    def __init__(
        self,
        issuer: str,
        scheme_name: Optional[str] = None,
        *,
        allowed_grant_types: List[GrantType] = [GrantType.AUTHORIZATION_CODE],
        auto_error: Optional[bool] = True,
        jwt_decode_options: Optional[JwtDecodeOptions] = None,
    ) -> None:
        self.well_known = fetch_well_known(issuer)
        self.jwks = fetch_jwks(self.well_known)
        self.jwt_decode_options = jwt_decode_options

        grant_types = set(self.well_known["grant_types_supported"])
        grant_types = grant_types.intersection(allowed_grant_types)

        oauth2_flows = OAuthFlowsModel()

        authz_url = self.well_known["authorization_endpoint"]
        token_url = self.well_known["token_endpoint"]

        if GrantType.AUTHORIZATION_CODE in grant_types:
            oauth2_flows.authorizationCode = OAuthFlowAuthorizationCode(
                authorizationUrl=authz_url,
                tokenUrl=token_url,
            )

        if GrantType.CLIENT_CREDENTIALS in grant_types:
            oauth2_flows.clientCredentials = OAuthFlowClientCredentials(
                tokenUrl=token_url
            )

        if GrantType.PASSWORD in grant_types:
            oauth2_flows.password = OAuthFlowPassword(tokenUrl=token_url)

        if GrantType.IMPLICIT in grant_types:
            oauth2_flows.implicit = OAuthFlowImplicit(authorizationUrl=authz_url)

        super().__init__(
            flows=oauth2_flows, scheme_name=scheme_name, auto_error=auto_error
        )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return jwt.decode(param, self.jwks, options=self.jwt_decode_options)
