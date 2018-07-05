local utils = require "kong.tools.utils"

local function check_user(anonymous)
  if anonymous == "" or utils.is_valid_uuid(anonymous) then
  	return true
  end
  return false, "the anonymous user must be empty or a valid uuid"
end

return {
  no_consumer = true,
  fields = {
    uri_param_names = {type = "array", default = {"paseto"}},
    cookie_names = {type = "array", default = {}},
    kid_claim_name = {type = "string", default = "kid"},
    claims_to_verify = {
      type = "table",
      schema = {
        flexible = true,
        fields = {
          claim = { type = "string" },
          value = { type = "string" },
        }
      }
    },
    anonymous = {type = "string", default = "", func = check_user},
    run_on_preflight = {type = "boolean", default = true},
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- perform any custom verification
    return true
  end
}
