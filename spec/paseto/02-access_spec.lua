local helpers = require "spec.helpers"
local json = require "cjson"
local paseto = require "paseto.v2"
local utils = require "kong.tools.utils"

local encode_base64 = ngx.encode_base64

for _, strategy in helpers.each_strategy() do
  describe("Plugin: paseto (access) [#" .. strategy .. "]", function()
    local proxy_client
    local secret_key_1, secret_key_3
    local payload_claims, footer_claims

    setup(function()
      local bp, _, dao = helpers.get_db_utils(strategy)

      local routes = {}

      for i = 1, 10 do
        routes[i] = bp.routes:insert {
          hosts = { "paseto" .. i .. ".com" },
        }
      end

      local consumers = bp.consumers
      local consumer1 = consumers:insert({ username = "paseto_tests_consumer_1" })
      local consumer3 = consumers:insert({ username = "paseto_tests_consumer_3" })
      local anonymous_user = consumers:insert({ username = "nobody" })

      secret_key_1, _ = paseto.generate_asymmetric_secret_key()
      local _, public_key_2 = paseto.generate_asymmetric_secret_key()
      secret_key_3, _ = paseto.generate_asymmetric_secret_key()

      payload_claims = {
        iss = "paragonie.com",
        jti = "87IFSGFgPNtQNNuw0AtuLttP",
        aud = "some-audience.com",
        sub = "test",
        iat = "2018-01-01T00:00:00+00:00",
        nbf = "2018-01-01T00:00:00+00:00",
        exp = "2099-01-01T00:00:00+00:00",
        data = "this is a signed message",
        myclaim = "required value"
      }
      footer_claims = { kid = "signature_verification_success" }

      dao.paseto_keys:insert {
        consumer_id = consumer1.id,
        kid = "signature_verification_fail",
        public_key = encode_base64(public_key_2)
      }

      dao.paseto_keys:insert {
        consumer_id = consumer3.id,
        kid = "signature_verification_success",
        secret_key = encode_base64(secret_key_3)
      }

      local plugins = bp.plugins

      plugins:insert({
        name     = "paseto",
        route_id = routes[1].id,
        config   = {},
      })

      plugins:insert({
        name     = "ctx-checker",
        route_id = routes[1].id,
        config   = { ctx_check_field = "authenticated_paseto_token" },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[2].id,
        config   = {
          claims_to_verify = {
            claim_1 = { claim = "IssuedBy", value = "paragonie.com" },
            claim_2 = { claim = "IdentifiedBy", value = "87IFSGFgPNtQNNuw0AtuLttP" },
            claim_3 = { claim = "ForAudience", value = "some-audience.com" },
            claim_4 = { claim = "Subject", value = "test" },
            claim_5 = { claim = "NotExpired", value = "true" },
            claim_6 = { claim = "ValidAt", value = "true" },
            claim_7 = { claim = "ContainsClaim", value = "data" },
            claim_8 = { claim = "myclaim", value = "required value" },
          }
        },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[3].id,
        config   = { run_on_preflight = false },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[4].id,
        config   = { cookie_names = { "choco", "berry" } },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[5].id,
        config   = { uri_param_names = { "token", "mypaseto" } },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[6].id,
        config   = { anonymous = anonymous_user.id },
      })

      plugins:insert({
        name     = "paseto",
        route_id = routes[7].id,
        config   = { anonymous = utils.uuid() },
      })

      assert(helpers.start_kong {
        database          = strategy,
        plugins           = "bundled, paseto, ctx-checker",
        real_ip_header    = "X-Forwarded-For",
        real_ip_recursive = "on",
        trusted_ips       = "0.0.0.0/0, ::/0",
        nginx_conf        = "spec/fixtures/custom_nginx.template",
      })

      proxy_client = helpers.proxy_client()
    end)

    teardown(function()
      if proxy_client then
        proxy_client:close()
      end
      helpers.stop_kong()
    end)

    describe("refusals", function()

      it("returns 401 Unauthorized if no PASETO is found in the request", function()
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto1.com",
          }
        })
        local json_body = json.decode(assert.res_status(401, res))
        assert.same({ message = "Unauthorized" }, json_body)
      end)

      it("returns 401 if the token is not in a valid PASETO format", function()
        local token = "v2.public"
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        local body = assert.res_status(401, res)
        local json_body = json.decode(body)
        assert.same({ message = "Bad token; Invalid token format" }, json_body)
      end)

      it("returns 401 if the token footer does not contain a kid claim", function()
        local footer_claims_2 = { no_kid_claim = "1234" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims_2)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        local body = assert.res_status(401, res)
        local json_body = json.decode(body)
        assert.same({ message = "No mandatory 'kid' in claims" }, json_body)
      end)

      it("returns 403 if no key with a kid matching the claim is found", function()
        local footer_claims_2 = { kid = "1234" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims_2)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        local body = assert.res_status(403, res)
        local json_body = json.decode(body)
        assert.same({ message = "No key found for given 'kid'" }, json_body)
      end)

      it("returns 403 when signature verification fails", function()
        local footer_claims_2 = { kid = "signature_verification_fail" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims_2)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        local body = assert.res_status(403, res)
        local json_body = json.decode(body)
        assert.same({ message = "Token verification failed; Invalid signature for this message" }, json_body)
      end)

      it("returns 403 when registered claims verification fails", function()
        local invalid_payload_claims = {
          iss = "paragonie.com",
          jti = "87IFSGFgPNtQNNuw0AtuLttP",
          aud = "some-audience.com",
          sub = "test",
          iat = "2018-01-01T00:00:00+00:00",
          nbf = "2018-01-01T00:00:00+00:00",
          exp = "2018-02-01T00:00:00+00:00",
          data = "this is a signed message",
          myclaim = "required value"
        }
        local token = paseto.sign(secret_key_3, invalid_payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto2.com",
          }
        })
        local body = assert.res_status(403, res)
        local json_body = json.decode(body)
        assert.same({ message = "Token verification failed; Token has expired" }, json_body)
      end)

      it("returns 403 when custom claims verification fails", function()
        local invalid_payload_claims = {
          iss = "paragonie.com",
          jti = "87IFSGFgPNtQNNuw0AtuLttP",
          aud = "some-audience.com",
          sub = "test",
          iat = "2018-01-01T00:00:00+00:00",
          nbf = "2018-01-01T00:00:00+00:00",
          exp = "2099-01-01T00:00:00+00:00",
          data = "this is a signed message",
          myclaim = "invalid"
        }
        local token = paseto.sign(secret_key_3, invalid_payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto2.com",
          }
        })
        local body = assert.res_status(403, res)
        local json_body = json.decode(body)
        assert.same({ message = "Token verification failed; Claim 'myclaim' does not match the expected value" }, json_body)
      end)

      it("returns 401 when the token is not found in the cookie 'banana'", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto4.com",
            ["Cookie"] = "banana=" .. token .. "; path=/;domain=.paseto4.com",
          }
        })
        local json_body = json.decode(assert.res_status(401, res))
        assert.same({ message = "Unauthorized" }, json_body)
      end)

      it("returns 403 when the token in cookies is malformed", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto4.com",
            ["Cookie"] = "berry=" .. "invalid" .. token .. "; path=/;domain=.paseto4.com",
          }
        })
        local json_body = json.decode(assert.res_status(403, res))
        assert.same({ message = "Token verification failed; Invalid message header" }, json_body)
      end)

      it("returns 401 when the token is not found in the URL parameter 'mytoken'", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request/?mytoken=" .. token,
          headers = {
            ["Host"] = "paseto5.com",
          }
        })
        local json_body = json.decode(assert.res_status(401, res))
        assert.same({ message = "Unauthorized" }, json_body)
      end)

      it("returns Unauthorized on OPTIONS requests if run_on_preflight is true", function()
        local res = assert(proxy_client:send {
          method  = "OPTIONS",
          path    = "/request",
          headers = {
            ["Host"] = "paseto1.com"
          }
        })
        local json_body = json.decode(assert.res_status(401, res))
        assert.same({ message = "Unauthorized" }, json_body)
      end)

    end)

    describe("successful requests", function()

      it("proxies the request on token verification", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal(authorization, body.headers.authorization)
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request on token and claims verification", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto2.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal(authorization, body.headers.authorization)
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request when the token is found in the cookie 'choco'", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto4.com",
            ["Cookie"] = "choco=" .. token .. "; path=/;domain=.paseto4.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request when the token is found in the cookie 'berry'", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto4.com",
            ["Cookie"] = "berry=" .. token .. "; path=/;domain=.paseto4.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request when the token is found in URL parameters", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request/?paseto=" .. token,
          headers = {
            ["Host"] = "paseto1.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request when the token is found in a custom URL parameter", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request/?token=" .. token,
          headers = {
            ["Host"] = "paseto5.com",
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("returns 200 on OPTIONS requests if run_on_preflight is false", function()
        local res = assert(proxy_client:send {
          method  = "OPTIONS",
          path    = "/request",
          headers = {
            ["Host"] = "paseto3.com"
          }
        })
        assert.res_status(200, res)
      end)

    end)

    describe("ctx.authenticated_paseto_token", function()

      it("is added to ngx.ctx when authenticated", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"]          = "paseto1.com",
          }
        })
        assert.res_status(200, res)
        local header = assert.header("ctx-checker-authenticated-paseto-token", res)
        assert.equal(token, header)
      end)

    end)

    describe("config.anonymous", function()

      it("proxies the request with valid credentials and anonymous", function()
        local token = paseto.sign(secret_key_3, payload_claims, footer_claims)
        local authorization = "Bearer " .. token
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Authorization"] = authorization,
            ["Host"] = "paseto6.com"
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("paseto_tests_consumer_3", body.headers["x-consumer-username"])
        assert.is_nil(body.headers["x-anonymous-consumer"])
      end)

      it("proxies the request with invalid credentials and anonymous", function()
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto6.com"
          }
        })
        local body = json.decode(assert.res_status(200, res))
        assert.equal("true", body.headers["x-anonymous-consumer"])
        assert.equal("nobody", body.headers["x-consumer-username"])
      end)

      it("errors when the specified anonymous user doesn't exist", function()
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto7.com"
          }
        })
        assert.response(res).has.status(500)
      end)

    end)

  end)

  describe("Plugin: paseto (access) [#" .. strategy .. "]", function()

    local client
    local user1
    local user2
    local anonymous
    local paseto_token
    local payload_claims, footer_claims

    setup(function()
      local bp, _, dao = helpers.get_db_utils(strategy)

      local service1 = bp.services:insert({
        path = "/request"
      })

      local route1 = bp.routes:insert {
        hosts     = { "logical-and.com" },
        service   = service1,
      }

      bp.plugins:insert {
        name     = "paseto",
        route_id = route1.id,
      }

      bp.plugins:insert {
        name     = "key-auth",
        route_id = route1.id,
      }

      anonymous = bp.consumers:insert {
        username = "Anonymous",
      }

      user1 = bp.consumers:insert {
        username = "Mickey",
      }

      user2 = bp.consumers:insert {
        username = "Aladdin",
      }

      local service2 = bp.services:insert({
        path = "/request"
      })

      local route2 = bp.routes:insert {
        hosts     = { "logical-or.com" },
        service   = service2,
      }

      bp.plugins:insert {
        name     = "paseto",
        route_id = route2.id,
        config   = {
          anonymous = anonymous.id,
        },
      }

      bp.plugins:insert {
        name     = "key-auth",
        route_id = route2.id,
        config   = {
          anonymous = anonymous.id,
        },
      }

      bp.keyauth_credentials:insert {
        key         = "Mouse",
        consumer_id = user1.id,
      }

      local secret_key = paseto.generate_asymmetric_secret_key()
      dao.paseto_keys:insert {
        consumer_id = user2.id,
        kid = "123456789",
        secret_key = encode_base64(secret_key)
      }

      payload_claims = {
        iss = "paragonie.com",
        jti = "87IFSGFgPNtQNNuw0AtuLttP",
        aud = "some-audience.com",
        sub = "test",
        iat = "2018-01-01T00:00:00+00:00",
        nbf = "2018-01-01T00:00:00+00:00",
        exp = "2099-01-01T00:00:00+00:00",
        data = "this is a signed message",
        myclaim = "required value"
      }
      footer_claims = { kid = "123456789" }

      paseto_token   = "Bearer " .. paseto.sign(secret_key, payload_claims, footer_claims)

      assert(helpers.start_kong({
        database   = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        custom_plugins = "paseto",
      }))

      client = helpers.proxy_client()
    end)

    teardown(function()
      if client then
        client:close()
      end
      helpers.stop_kong()
    end)

    describe("multiple auth without anonymous, logical AND", function()

      it("passes with all credentials provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"]          = "logical-and.com",
            ["apikey"]        = "Mouse",
            ["Authorization"] = paseto_token,
          }
        })
        assert.response(res).has.status(200)
        assert.request(res).has.no.header("x-anonymous-consumer")
        local id = assert.request(res).has.header("x-consumer-id")
        assert.not_equal(id, anonymous.id)
        assert(id == user1.id or id == user2.id)
      end)

      it("fails 401, with only the first credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"]   = "logical-and.com",
            ["apikey"] = "Mouse",
          }
        })
        assert.response(res).has.status(401)
      end)

      it("fails 401, with only the second credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "logical-and.com",
            ["Authorization"] = paseto_token,
          }
        })
        assert.response(res).has.status(401)
      end)

      it("fails 401, with no credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "logical-and.com",
          }
        })
        assert.response(res).has.status(401)
      end)

    end)

    describe("multiple auth with anonymous, logical OR", function()

      it("passes with all credentials provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"]          = "logical-or.com",
            ["apikey"]        = "Mouse",
            ["Authorization"] = paseto_token,
          }
        })
        assert.response(res).has.status(200)
        assert.request(res).has.no.header("x-anonymous-consumer")
        local id = assert.request(res).has.header("x-consumer-id")
        assert.not_equal(id, anonymous.id)
        assert(id == user1.id or id == user2.id)
      end)

      it("passes with only the first credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"]   = "logical-or.com",
            ["apikey"] = "Mouse",
          }
        })
        assert.response(res).has.status(200)
        assert.request(res).has.no.header("x-anonymous-consumer")
        local id = assert.request(res).has.header("x-consumer-id")
        assert.not_equal(id, anonymous.id)
        assert.equal(user1.id, id)
      end)

      it("passes with only the second credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"]          = "logical-or.com",
            ["Authorization"] = paseto_token,
          }
        })
        assert.response(res).has.status(200)
        assert.request(res).has.no.header("x-anonymous-consumer")
        local id = assert.request(res).has.header("x-consumer-id")
        assert.not_equal(id, anonymous.id)
        assert.equal(user2.id, id)
      end)

      it("passes with no credential provided", function()
        local res = assert(client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "logical-or.com",
          }
        })
        assert.response(res).has.status(200)
        assert.request(res).has.header("x-anonymous-consumer")
        local id = assert.request(res).has.header("x-consumer-id")
        assert.equal(id, anonymous.id)
      end)

    end)

  end)
end
