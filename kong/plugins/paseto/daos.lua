local utils = require "kong.tools.utils"
local Errors = require "kong.dao.errors"
local paseto = require "paseto.v2"

local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

local SCHEMA = {
  primary_key = {"id"},
  table = "paseto_keys",
  cache_key = { "kid" },
  fields = {
    id = {type = "id", dao_insert_value = true},
    created_at = {type = "timestamp", immutable = true, dao_insert_value = true},
    consumer_id = {type = "id", required = true, foreign = "consumers:id"},
    kid = {type = "string", unique = true, default = utils.random_string},
    secret_key = {type = "string"},
    public_key = {type = "string"},
  },
  self_check = function(schema, plugin_t, dao, is_update)
    if plugin_t.public_key == nil then
      if plugin_t.secret_key == nil then
        -- If no secret key or public key is supplied a key pair is generated
        local secret_key, public_key = paseto.generate_asymmetric_secret_key()
        plugin_t.secret_key = encode_base64(secret_key)
        plugin_t.public_key = encode_base64(public_key)
        if plugin_t.public_key == nil then
          return false, Errors.schema "public_key format is invalid"
        end
      else
        -- If a secret key is supplied the last 32 bytes is assumed to be the public key
        local decoded_secret_key = decode_base64(plugin_t.secret_key)
        if #decoded_secret_key ~= 64 then
          return false, Errors.schema "secret_key must be a base64 encoded 64 byte string"
        end
        plugin_t.public_key = encode_base64(string.sub(decoded_secret_key, 33, 64))
      end
    else
      local decoded_public_key = decode_base64(plugin_t.public_key)
      if #decoded_public_key ~= 32 then
        return false, Errors.schema "public_key must be a base64 encoded 32 byte string"
      end
      -- If a key pair is supplied they must match
      if plugin_t.secret_key ~= nil then
        local decoded_secret_key = decode_base64(plugin_t.secret_key)
        if #decoded_secret_key ~= 64 then
          return false, Errors.schema "secret_key must be a base64 encoded 64 byte string"
        end
        if string.sub(decoded_secret_key, 33, 64) ~= decoded_public_key then
          return false, Errors.schema "secret_key and public_key must be a matching key pair"
        end    
      end
    end
    return true
  end,
}

return {paseto_keys = SCHEMA}
