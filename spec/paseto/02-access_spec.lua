local helpers = require "spec.helpers"
local json = require "cjson"
local paseto = require "paseto.v2"

local encode_base64 = ngx.encode_base64

for _, strategy in helpers.each_strategy() do
  describe("Plugin: paseto (access) [#" .. strategy .. "]", function()
    local proxy_client
    local secret_key_1, secret_key_3

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
      --local consumer2 = consumers:insert({ username = "paseto_tests_consumer_2" })
      local consumer3 = consumers:insert({ username = "paseto_tests_consumer_3" })

      secret_key_1, _ = paseto.generate_asymmetric_secret_key()
      local _, public_key_2 = paseto.generate_asymmetric_secret_key()
      secret_key_3, _ = paseto.generate_asymmetric_secret_key()

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
        route_id = routes[10].id,
        config   = { cookie_names = { "choco", "berry" } },
      })

      assert(helpers.start_kong {
        database = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        custom_plugins = "paseto",
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

      local payload_claims

      setup(function()
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
      end)

      it("returns 401 Unauthorized if no PASETO is found in the request", function()
        local res = assert(proxy_client:send {
          method  = "GET",
          path    = "/request",
          headers = {
            ["Host"] = "paseto1.com",
          }
        })
        assert.res_status(401, res)
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
        assert.same({ message = "Invalid token format" }, json_body)
      end)

      -- TODO: add more tests for token parsing

      it("returns 401 if the token footer does not contain a kid claim", function()
        local footer_claims = { no_kid_claim = "1234" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims)
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

      it("returns 403 if no keys with a kid matching the claim are found", function()
        local footer_claims = { kid = "1234" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims)
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
        assert.same({ message = "No keys found for given 'kid'" }, json_body)
      end)

      it("returns 403 when signature verification fails", function()
        local footer_claims = { kid = "signature_verification_fail" }
        local token = paseto.sign(secret_key_1, payload_claims, footer_claims)
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
        assert.same({ message = "Invalid signature for this message" }, json_body)
      end)

      it("returns 403 when claims verification fails", function()
        local footer_claims = { kid = "signature_verification_success" }
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
        assert.same({ message = "Claim 'myclaim' does not match the expected value" }, json_body)
      end)

    end)

    describe("success cases", function()

      local payload_claims, footer_claims

      setup(function()
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
      end)

      it("returns 200 on successful authentication", function()
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
      end)

      it("returns 200 on successful authentication with claims validation", function()
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
        assert.res_status(200, res)
      end)

    end)

  end)

   -- TODO: add multiple auth tests
  
end
