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
        route_id = routes[10].id,
        config   = { cookie_names = { "choco", "berry" } },
      })

      --assert(helpers.dao:run_migrations())
      --assert(helpers.kong_exec("migrations up -c spec/kong_tests.conf", {}))

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
        local payload_claims, footer_claims
        payload_claims = {}
        payload_claims["clientid"] = 100099
        payload_claims["myclaim"] = "value"
        footer_claims = { no_kid_claim = "1234" }

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
        local payload_claims, footer_claims
        payload_claims = {}
        payload_claims["clientid"] = 100099
        payload_claims["myclaim"] = "value"
        footer_claims = { kid = "1234" }

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
        local payload_claims, footer_claims
        payload_claims = {}
        payload_claims["clientid"] = 100099
        payload_claims["myclaim"] = "value"
        footer_claims = { kid = "signature_verification_fail" }

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
        assert.same({ message = "Invalid signature" }, json_body)
      end)



    end)

    describe("success cases", function()

      it("returns 200 on successful authentication", function()
        local payload_claims, footer_claims
        payload_claims = {}
        payload_claims["clientid"] = 100099
        payload_claims["myclaim"] = "value"
        footer_claims = { kid = "signature_verification_success" }

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

    end)





  end)

   -- TODO: add multiple auth tests
  
end
