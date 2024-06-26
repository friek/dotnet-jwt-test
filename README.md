# Another sandbox project
This one is to test how authentication works when using JWTs as auth
method. My main curiosity was how loose JWTs get validated.

## JWT validation
I've tested this by using a keycloak OIDC authority. Using the following
command, you can generate a JWT token for a keycloak user:
```bash
curl -L -X POST https://<keycloak url>/realms/<realm name>/protocol/openid-connect/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=<client id>' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_secret=<client secret>' \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'username=<username>' \
    --data-urlencode 'password=<password>' | \
    jq -r .access_token
```

Additionally, configure `OIDC:Authority` in your secrets or in appsettings.json.

Then, run the "weather forecast" service and test authentication as follows:
```bash
curl -v -H "Authorization: Bearer <JWT>" http://localhost:5165/WeatherForecast
```

The first time an authentication request is made, the application will request `https://<keycloak url>/realms/<realm name>/protocol/openid-connect/certs`
which contains the public keys of the issued JWT. I'm not sure if it's being
cached for a certain time or for the remainder of the application runtime,
but subsequent calls to the weather forecast service will not trigger the request
again. I would find it logical that it's only being cached for a certain time.

The certs URL mentioned above is coming from the OpenID configuration.
Before the certs call, `https://<keycloak url>/realms/<realm name>/.well-known/openid-configuration`
is retrieved to determine the URL configured in `jwks_uri`, which in case of
keycloak is the /certs url. The /certs URL returns a JSON struct defined in [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517).   
This flow is also explained on [this auth0 page](https://auth0.com/docs/secure/tokens/json-web-tokens/locate-json-web-key-sets).