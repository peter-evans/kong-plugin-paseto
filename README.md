# [PASETO](https://paseto.io/) (Platform-Agnostic Security Tokens) plugin for [Kong](https://konghq.com/)
[![luarocks](https://img.shields.io/badge/luarocks-kong--plugin--paseto-blue.svg)](https://luarocks.org/modules/peterevans/kong-plugin-paseto)
[![Build Status](https://travis-ci.org/peter-evans/kong-plugin-paseto.svg?branch=master)](https://travis-ci.org/peter-evans/kong-plugin-paseto)
[![Coverage Status](https://coveralls.io/repos/github/peter-evans/kong-plugin-paseto/badge.svg?branch=master)](https://coveralls.io/github/peter-evans/kong-plugin-paseto?branch=master)

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation for secure stateless tokens.

>__*"Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)."*__

— [paragonie/paseto](https://github.com/paragonie/paseto)

## Plugin Description
Verify requests containing signed PASETOs (as specified in [PASETO RFC](https://paseto.io/rfc/)).
Each of your Consumers will have PASETO credentials (public and secret keys) which must be used to sign their PASETOs.
A token can then be passed through:

- a query string parameter,
- a cookie,
- or the Authorization header.

The plugin will either proxy the request to your upstream services if the token's signature is verified, or discard the request if not.
The plugin can also perform verifications on registered claims and custom claims.

## Feature Support

- v2.public JSON payload PASETOs
- Registered claims validation
- Custom claims validation

## Installation

#### Sodium Crypto Library

This plugin uses the [PASETO for Lua](https://github.com/peter-evans/paseto-lua) library, which in turn depends on the [Sodium crypto library (libsodium)](https://github.com/jedisct1/libsodium).
The following is a convenient way to install libsodium via LuaRocks.
I don't necessarily recommend this for production use. Please see [libsodium's documentation](https://download.libsodium.org/doc/installation/) for full installation instructions.
```
luarocks install libsodium
```
Note: The Sodium Crypto Library must be installed on each node in your Kong cluster.

#### PASETO Kong Plugin
Install the plugin on each node in your Kong cluster via luarocks:
```
luarocks install kong-plugin-paseto
```
Add to the custom_plugins list in your Kong configuration (on each Kong node):
```
custom_plugins = paseto
```

## Configuration

#### Enabling the plugin on a Service
Configure this plugin on a Service by making the following request:
```
$ curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=paseto"
```
`service`: the id or name of the Service that this plugin configuration will target.

#### Enabling the plugin on a Route
Configure this plugin on a Route with:
```
$ curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=paseto"
```
`route_id`: the id of the Route that this plugin configuration will target.

#### Enabling the plugin on an API
If you are using an older version of Kong with the legacy API entity (deprecated since 0.13.0), you can configure this plugin on top of such an API by making the following request:
```
$ curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=paseto"
```
`api`: either id or name of the API that this plugin configuration will target.

#### Global plugins
All plugins can be configured using the http://kong:8001/plugins/ endpoint. A plugin which is not associated to any Service, Route or Consumer (or API, if you are using an older version of Kong) is considered "global", and will be run on every request.

#### Parameters
Here's a list of all the parameters which can be used in this plugin's configuration:

| Parameter |  | Default | Description |
| :---: | :---: | :---: | :---: |
| `name` |  |  | The name of the plugin to use, in this case `paseto`. |
| `service_id` |  |  | The id of the Service which this plugin will target. |
| `route_id` |  |  | The id of the Route which this plugin will target. |
| `enabled` |  | `true` | Whether this plugin will be applied. |
| `api_id` |  |  | The id of the API which this plugin will target. Note: The API Entity is deprecated since Kong 0.13.0. |
| `config.uri_param_names` | optional | `paseto` | A list of querystring parameters that the plugin will inspect to retrieve PASETOs. |
| `config.cookie_names` | optional |  | A list of cookie names that the plugin will inspect to retrieve PASETOs. |
| `config.claims_to_verify.{claim_name}` | optional |  | This is a list of custom objects that you can set, with arbitrary names set in the `{claim_name}` placeholder, like `config.claims_to_verify.claim_1.claim=ForAudience` if your object is called "claim_1". |
| `config.claims_to_verify.{claim_name}.claim` |  |  | The claim rule or name of your custom claim. See below for a description of the claim rules. |
| `config.claims_to_verify.{claim_name}.value` |  |  | The value to verify against. |
| `config.kid_claim_name` | optional | `kid` | The name of the claim in which the `kid` identifying the PASETO key pair **must** be passed. The plugin will attempt to read this claim from the PASETO footer. |
| `config.anonymous` | optional |  | An optional string (consumer uuid) value to use as an "anonymous" consumer if authentication fails. If empty (default), the request will fail with an authentication failure `4xx`. Please note that this value must refer to the Consumer `id` attribute which is internal to Kong, and **not** its `custom_id`. |
| `config.run_on_preflight` | optional | `true` | A boolean value that indicates whether the plugin should run (and try to authenticate) on `OPTIONS` preflight requests, if set to `false` then `OPTIONS` requests will always be allowed. |

#### Claim Rules

* `ForAudience` which compares the payload-provided `aud` claim with an expected value.
* `IdentifiedBy` which compares the payload-provided `jti` claim with an expected value.
* `IssuedBy` which compares the payload-provided `iss` claim with an expected value.
* `NotExpired` which verifies that the current time is less than or equal to the DateTime stored in the `exp` claim.
* `Subject` which compares the payload-provided `sub` claim with an expected value.
* `ValidAt` which verifies all of the following:
   * The current time is less than or equal to the DateTime stored in the `exp` claim.
   * The current time is greater than or equal to the DateTime stored in the `iat` claim.
   * The current time is greater than or equal to the DateTime stored in the `nbf` claim.
* `ContainsClaim` which verifies that the payload contains a claim with the specified name.
* `{custom_claim}` which verifies that the payload contains a claim with the name set in the `{claim_name}` placeholder and with an expected value.

## Usage

In order to use the plugin, you first need to create a Consumer and associate one or more PASETO credentials (holding the public key used to verify the token) to it. The Consumer represents a developer using the final service.

#### Create a Consumer

You need to associate a credential to an existing Consumer object. To create a Consumer, you can execute the following request:

```bash
$ curl -X POST http://kong:8001/consumers \
    --data "username=<USERNAME>" \
    --data "custom_id=<CUSTOM_ID>"
HTTP/1.1 201 Created
```

| Parameter |  | Default | Description |
| :---: | :---: | :---: | :---: |
| `username` | semi-optional |  | The username for this Consumer. Either this field or `custom_id` must be specified. |
| `custom_id` | semi-optional |  | A custom identifier used to map the Consumer to an external database. Either this field or `username` must be specified. |

A Consumer can have many PASETO credentials.

#### Create a PASETO credential

You can provision a new PASETO credential by issuing the following HTTP request:

```bash
$ curl -X POST http://kong:8001/consumers/{consumer}/paseto -H "Content-Type: application/x-www-form-urlencoded"
HTTP/1.1 201 Created

{
   "consumer_id": "94c058d0-f5f1-4afc-ab18-eab487492a03",
   "created_at": 1530751342000,
   "id": "f99c0041-6271-43d3-bebd-32479c2746b6",
   "kid": "ikypl5x7QEKShEoEzFxfz5axONlgjdza",
   "public_key": "8SQDqtA5yx4atQEg0uH3Rit3nLq+EAQF4A1Zkvwh5TU=",
   "secret_key": "hbJbxFK3xFL1YlrcqodKqt0FvVyZjmPXQqOIexzxsVbxJAOq0DnLHhq1ASDS4fdGK3ecur4QBAXgDVmS/CHlNQ=="
}
```

- `consumer`: The `id` or `username` property of the Consumer entity to associate the credentials to.

| Parameter |  | Default | Description |
| :---: | :---: | :---: | :---: |
| `kid` | optional |  | A unique string identifying the credential. If left out, it will be auto-generated. |
| `secret_key` | optional |  | The 64 byte secret key base64 encoded. |
| `public_key` | optional |  | The 32 byte public key base64 encoded. If left out and a `secret_key` is supplied, the `public_key` is assumed to be the last 32 bytes of the `secret_key`. |

If neither `secret_key` or `public_key` are supplied the plugin will generate a new key pair.

#### Delete a PASETO credential

You can remove a Consumer's PASETO credential by issuing the following HTTP
request:

```bash
$ curl -X DELETE http://kong:8001/consumers/{consumer}/paseto/{id}
HTTP/1.1 204 No Content
```

- `consumer`: The `id` or `username` property of the Consumer entity to associate the credentials to.
- `id`: The `id` of the PASETO credential.

#### List PASETO credentials

You can list a Consumer's PASETO credentials by issuing the following HTTP
request:

```bash
$ curl -X GET http://kong:8001/consumers/{consumer}/paseto
HTTP/1.1 200 OK
```

- `consumer`: The `id` or `username` property of the Consumer entity to list credentials for.

```json
{
    "data": [
        {
           "consumer_id": "94c058d0-f5f1-4afc-ab18-eab487492a03",
           "created_at": 1530751342000,
           "id": "f99c0041-6271-43d3-bebd-32479c2746b6",
           "kid": "ikypl5x7QEKShEoEzFxfz5axONlgjdza",
           "public_key": "8SQDqtA5yx4atQEg0uH3Rit3nLq+EAQF4A1Zkvwh5TU=",
           "secret_key": "hbJbxFK3xFL1YlrcqodKqt0FvVyZjmPXQqOIexzxsVbxJAOq0DnLHhq1ASDS4fdGK3ecur4QBAXgDVmS/CHlNQ=="
        }
    ],
    "total": 1
}
```

#### Send a request with a PASETO

PASETOs can now be included in a request to Kong by adding it to the `Authorization` header:

```bash
$ curl http://kong:8000/{route path} \
    -H 'Authorization: Bearer v2.public.eyJuYmYiOiIyMDE4LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQwMDowMDowMCswMDowMCIsImlzcyI6InBhcmFnb25pZS5jb20iLCJhdWQiOiJzb21lLWF1ZGllbmNlLmNvbSIsImRhdGEiOiJ0aGlzIGlzIGEgc2lnbmVkIG1lc3NhZ2UiLCJleHAiOiIyMDk5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIiwic3ViIjoidGVzdCIsIm15Y2xhaW0iOiJyZXF1aXJlZCB2YWx1ZSJ9-8bFBx9Z5665JK3Rfwl3v2rx-etZ0H-EAkmbOdt1VI4h3gDzMsqUR2pRRdBvzPiv5cPDQqmaJ1gcqnXR3P0BDQ.eyJraWQiOiJzaWduYXR1cmVfdmVyaWZpY2F0aW9uX3N1Y2Nlc3MifQ'
```

as a querystring parameter, if configured in `config.uri_param_names` (which contains `paseto` by default):

```bash
$ curl http://kong:8000/{route path}?paseto=v2.public.eyJuYmYiOiIyMDE4LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQwMDowMDowMCswMDowMCIsImlzcyI6InBhcmFnb25pZS5jb20iLCJhdWQiOiJzb21lLWF1ZGllbmNlLmNvbSIsImRhdGEiOiJ0aGlzIGlzIGEgc2lnbmVkIG1lc3NhZ2UiLCJleHAiOiIyMDk5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIiwic3ViIjoidGVzdCIsIm15Y2xhaW0iOiJyZXF1aXJlZCB2YWx1ZSJ9-8bFBx9Z5665JK3Rfwl3v2rx-etZ0H-EAkmbOdt1VI4h3gDzMsqUR2pRRdBvzPiv5cPDQqmaJ1gcqnXR3P0BDQ.eyJraWQiOiJzaWduYXR1cmVfdmVyaWZpY2F0aW9uX3N1Y2Nlc3MifQ
```

or as cookie, if the name is configured in `config.cookie_names` (which is not enabled by default):

```bash
curl --cookie paseto=v2.public.eyJuYmYiOiIyMDE4LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQwMDowMDowMCswMDowMCIsImlzcyI6InBhcmFnb25pZS5jb20iLCJhdWQiOiJzb21lLWF1ZGllbmNlLmNvbSIsImRhdGEiOiJ0aGlzIGlzIGEgc2lnbmVkIG1lc3NhZ2UiLCJleHAiOiIyMDk5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIiwic3ViIjoidGVzdCIsIm15Y2xhaW0iOiJyZXF1aXJlZCB2YWx1ZSJ9-8bFBx9Z5665JK3Rfwl3v2rx-etZ0H-EAkmbOdt1VI4h3gDzMsqUR2pRRdBvzPiv5cPDQqmaJ1gcqnXR3P0BDQ.eyJraWQiOiJzaWduYXR1cmVfdmVyaWZpY2F0aW9uX3N1Y2Nlc3MifQ http://kong:8000/{route path}
```

Note: When the PASETO is valid and proxied to the upstream service, Kong makes no modification to the request other than adding headers identifying the Consumer. The PASETO will be forwarded to your upstream service, which can assume its validity. It is now the role of your service to base64 decode the PASETO claims and make use of them.

## License

MIT License - see the [LICENSE](LICENSE) file for details
