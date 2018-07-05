local helpers = require "spec.helpers"
local cjson = require "cjson"
local fixtures = require "spec.paseto.fixtures"
local utils    = require "kong.tools.utils"

for _, strategy in helpers.each_strategy() do
  describe("Plugin: paseto (API) [#" .. strategy .. "]", function()
    local admin_client
    local bp, dao
    local consumer, paseto_key

    setup(function()
      bp, _, dao = helpers.get_db_utils(strategy)

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

        it("raises the error 'secret_key must be a base64 encoded 64 byte string'", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              secret_key = fixtures.public_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(400, res))
          assert.equal("secret_key must be a base64 encoded 64 byte string", body.message)
        end)

        it("raises the error 'public_key must be a base64 encoded 32 byte string'", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              public_key = fixtures.secret_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(400, res))
          assert.equal("public_key must be a base64 encoded 32 byte string", body.message)
        end)

        it("raises the error 'secret_key must be a base64 encoded 64 byte string'", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              secret_key = fixtures.public_key_1,
              public_key = fixtures.public_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(400, res))
          assert.equal("secret_key must be a base64 encoded 64 byte string", body.message)
        end)

        it("raises the error 'secret_key and public_key must be a matching key pair'", function()
          local res = assert(admin_client:send {
            method = "POST",
            path = "/consumers/bob/paseto/",
            body = {
              secret_key = fixtures.secret_key_2,
              public_key = fixtures.public_key_1
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(400, res))
          assert.equal("secret_key and public_key must be a matching key pair", body.message)
        end)

      end)

      describe("PUT", function()

        it("creates and updates a paseto key", function()
          local res = assert(admin_client:send {
            method = "PUT",
            path = "/consumers/bob/paseto/",
            body = {},
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = cjson.decode(assert.res_status(201, res))
          assert.equal(consumer.id, body.consumer_id)

          -- For GET tests
          paseto_key = body
        end)

      end)

      describe("GET", function()

        it("retrieves all", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/consumers/bob/paseto/",
          })
          local body = cjson.decode(assert.res_status(200, res))
          assert.equal(5, #(body.data))
        end)

      end)

    end)

    describe("/consumers/:consumer/paseto/:id", function()

      describe("GET", function()

        it("retrieves by id", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/consumers/bob/paseto/" .. paseto_key.id,
          })
          assert.res_status(200, res)
        end)

        it("retrieves by kid", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/consumers/bob/paseto/" .. paseto_key.kid,
          })
          assert.res_status(200, res)
        end)

      end)

      describe("PATCH", function()

        it("updates a paseto key by id", function()
          local res = assert(admin_client:send {
            method = "PATCH",
            path = "/consumers/bob/paseto/" .. paseto_key.id,
            body = {
              kid = "alice",
              secret_key = fixtures.secret_key_2,
              public_key = fixtures.public_key_2
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = assert.res_status(200, res)
          paseto_key = cjson.decode(body)
          assert.equal(fixtures.secret_key_2, paseto_key.secret_key)
        end)

        it("updates a paseto key by kid", function()
          local res = assert(admin_client:send {
            method = "PATCH",
            path = "/consumers/bob/paseto/" .. paseto_key.kid,
            body = {
              kid = "alice",
              secret_key = fixtures.secret_key_3,
              public_key = fixtures.public_key_3
            },
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          local body = assert.res_status(200, res)
          paseto_key = cjson.decode(body)
          assert.equal(fixtures.secret_key_3, paseto_key.secret_key)
        end)

      end)

      describe("DELETE", function()

        it("deletes a paseto key", function()
          local res = assert(admin_client:send {
            method = "DELETE",
            path = "/consumers/bob/paseto/" .. paseto_key.id,
            body = {},
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          assert.res_status(204, res)
        end)

        it("returns 404 on attempting to delete non-existing paseto keys", function()
          local res = assert(admin_client:send {
            method = "DELETE",
            path = "/consumers/bob/paseto/" .. "blah",
            body = {},
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          assert.res_status(404, res)

         local res = assert(admin_client:send {
            method = "DELETE",
            path = "/consumers/bob/paseto/" .. "00000000-0000-0000-0000-000000000000",
            body = {},
            headers = {
              ["Content-Type"] = "application/json"
            }
          })
          assert.res_status(404, res)
        end)

      end)

    end)

    describe("/paseto", function()
      local consumer2

      describe("GET", function()

        setup(function()
          dao:truncate_table("paseto_keys")
          assert(dao.paseto_keys:insert {
            consumer_id = consumer.id,
          })
          consumer2 = assert(dao.consumers:insert {
            username = "bob-the-buidler"
          })
          assert(dao.paseto_keys:insert {
            consumer_id = consumer2.id,
          })
        end)

        it("retrieves all the pasetos with trailing slash", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos/"
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(2, #json.data)
          assert.equal(2, json.total)
        end)

        it("retrieves all the pasetos without trailing slash", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos"
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(2, #json.data)
          assert.equal(2, json.total)
        end)

        it("paginates through the pasetos", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos?size=1",
          })
          local body = assert.res_status(200, res)
          local json_1 = cjson.decode(body)
          assert.is_table(json_1.data)
          assert.equal(1, #json_1.data)
          assert.equal(2, json_1.total)

          res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos",
            query = {
              size = 1,
              offset = json_1.offset,
            }
          })
          body = assert.res_status(200, res)
          local json_2 = cjson.decode(body)
          assert.is_table(json_2.data)
          assert.equal(1, #json_2.data)
          assert.equal(2, json_2.total)

          assert.not_same(json_1.data, json_2.data)
          -- Disabled: on Cassandra, the last page still returns a
          -- next_page token, and thus, an offset proprty in the
          -- response of the Admin API.
          --assert.is_nil(json_2.offset) -- last page
        end)

        it("retrieve pasetos for a consumer_id", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos?consumer_id=" .. consumer.id
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(1, #json.data)
          assert.equal(1, json.total)
        end)

        it("return empty for a non-existing consumer_id", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos?consumer_id=" .. utils.uuid(),
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(0, #json.data)
          assert.equal(0, json.total)
        end)

      end)
    end)

    describe("/pasetos/:paseto_kid_or_id/consumer", function()

      describe("GET", function()
        local paseto_key
        setup(function()
          dao:truncate_table("paseto_keys")
          paseto_key = assert(dao.paseto_keys:insert {
            consumer_id = consumer.id
          })
        end)

        it("retrieve consumer from a paseto id", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos/" .. paseto_key.id .. "/consumer"
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.same(consumer,json)
        end)

        it("retrieve consumer from a paseto kid", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos/" .. paseto_key.kid .. "/consumer"
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.same(consumer,json)
        end)

        it("returns 404 for a random non-existing paseto id", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos/" .. utils.uuid()  .. "/consumer"
          })
          assert.res_status(404, res)
        end)

        it("returns 404 for a random non-existing paseto key", function()
          local res = assert(admin_client:send {
            method = "GET",
            path = "/pasetos/" .. utils.random_string()  .. "/consumer"
          })
          assert.res_status(404, res)
        end)

      end)

    end)

  end)
end
