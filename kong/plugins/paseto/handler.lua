local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local paseto = require "paseto.v2"

local string_format  = string.format
local ngx_re_gmatch  = ngx.re.gmatch
local ngx_set_header = ngx.req.set_header
local get_method = ngx.req.get_method
local decode_base64 = ngx.decode_base64

local plugin = require("kong.plugins.base_plugin"):extend()

plugin.PRIORITY = 1006
plugin.VERSION = "0.1.0"

function plugin:new()
  plugin.super.new(self, "paseto")
end

local function load_credential(paseto_kid)
  local rows, err = singletons.dao.paseto_keys:find_all {kid = paseto_kid}
  if err then
    return nil, err
  end
  return rows[1]
end

local function retrieve_token(request, conf)
  local uri_parameters = request.get_uri_args()

  for _, v in ipairs(conf.uri_param_names) do
    if uri_parameters[v] then
      return uri_parameters[v]
    end
  end

  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local paseto_cookie = ngx_var["cookie_" .. v]
    if paseto_cookie and paseto_cookie ~= "" then
      return paseto_cookie
    end
  end

  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

local function load_consumer(consumer_id, anonymous)
  local result, err = singletons.dao.consumers:find { id = consumer_id }
  if not result then
    if anonymous and not err then
      err = 'anonymous consumer "' .. consumer_id .. '" not found'
    end
    return nil, err
  end
  return result
end

local function set_consumer(consumer, paseto_key, token)
  ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  ngx.ctx.authenticated_consumer = consumer
  if paseto_key then
    ngx.ctx.authenticated_credential = paseto_key
    ngx.ctx.authenticated_jwt_token = token
    ngx_set_header(constants.HEADERS.ANONYMOUS, nil) -- in case of auth plugins concatenation
  else
    ngx_set_header(constants.HEADERS.ANONYMOUS, true)
  end
end

local function do_authentication(conf)
  local token, err = retrieve_token(ngx.req, conf)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" then
      return false, {status = 401}
    elseif ttype == "table" then
      return false, {status = 401, message = "Multiple tokens provided"}
    else
      return false, {status = 401, message = "Unrecognizable token"}
    end
  end

  -- Extract the footer claims
  local footer_claims, footer, err = paseto.extract_footer_claims(token)
  if footer_claims == nil then
    return false, {status = 401, message = err}
  end

  -- Retrieve the kid
  local kid = footer_claims[conf.kid_claim_name]
  if not kid then
    return false, {status = 401, message = "No mandatory '" .. conf.kid_claim_name .. "' in claims"}
  end

  -- Retrieve the public key
  local paseto_key_cache_key = singletons.dao.paseto_keys:cache_key(kid)
  local paseto_key, err      = singletons.cache:get(paseto_key_cache_key, nil, load_credential, kid)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  if not paseto_key then
    return false, {status = 403, message = "No keys found for given '" .. conf.kid_claim_name .. "'"}
  end

  -- Retrieve public key
  local public_key = decode_base64(paseto_key.public_key)
  if not public_key then
    return false, {status = 403, message = "Invalid public key"}
  end

  -- Verify the token signature
  local verified_claims = paseto.verify(public_key, token, nil, footer)
  if not verified_claims then
    return false, {status = 403, message = "Invalid signature"}
  end

  -- Verify claims


  -- Retrieve the consumer
  local consumer_cache_key = singletons.dao.consumers:cache_key(paseto_key.consumer_id)
  local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                  load_consumer,
                                                  paseto_key.consumer_id, true)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  if not consumer then
    -- Should never occur
    return false, {status = 403, message = string_format("Could not find consumer for '%s=%s'", conf.kid_claim_name, paseto_key)}
  end

  set_consumer(consumer, paseto_key, token)

  return true
end

function plugin:access(conf)
  plugin.super.access(self)

  -- check if preflight request and whether it should be authenticated
  if not conf.run_on_preflight and get_method() == "OPTIONS" then
    return
  end

  if ngx.ctx.authenticated_credential and conf.anonymous ~= "" then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    if conf.anonymous ~= "" then
      -- get anonymous user
      local consumer_cache_key = singletons.dao.consumers:cache_key(conf.anonymous)
      local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                      load_consumer,
                                                      conf.anonymous, true)
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      end
      set_consumer(consumer, nil, nil)
    else
      return responses.send(err.status, err.message)
    end
  end
end

return plugin
