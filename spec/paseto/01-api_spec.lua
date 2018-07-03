local helpers  = require "spec.helpers"
local cjson    = require "cjson"
local fixtures = require "spec.paseto.fixtures"
--local utils    = require "kong.tools.utils"

for _, strategy in helpers.each_strategy() do
  describe("Plugin: paseto (API) [#" .. strategy .. "]", function()
    local admin_client
    local bp

    setup(function()
      bp = helpers.get_db_utils(strategy)

      assert(helpers.start_kong {
        database = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        custom_plugins = "paseto",
      })

      admin_client = helpers.admin_client()
    end)

    teardown(function()
      if admin_client then
        admin_client:close()
      end

      helpers.stop_kong()
    end)

    describe("/consumers/:consumer/paseto/", function()

    local consumer

      setup(function()
        consumer = bp.consumers:insert {
          username = "bob"
        }
        bp.consumers:insert {
          username = "alice"
        }
      end)

      describe("POST", function()

        it("creates a paseto key pair", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {},
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(201, res))
          assert.equal(consumer.id, body.consumer_id)
        end)

        it("accepts a base64 encoded secret key of length 64 bytes", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              secret_key = fixtures.secret_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(201, res))
          assert.equal(fixtures.secret_key_1, body.secret_key)
        end)

        it("accepts a base64 encoded public key of length 32 bytes", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              public_key = fixtures.public_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(201, res))
          assert.equal(fixtures.public_key_1, body.public_key)
        end)

        it("accepts a base64 encoded matching key pair", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              kid = fixtures.kid_1,
              secret_key = fixtures.secret_key_1,
              public_key = fixtures.public_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(201, res))
          assert.equal(fixtures.kid_1, body.kid)
          assert.equal(fixtures.secret_key_1, body.secret_key)
          assert.equal(fixtures.public_key_1, body.public_key)
        end)

        -- TODO: errors
      end)



    end)
  end)
end
