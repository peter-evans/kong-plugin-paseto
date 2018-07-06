local crud = require "kong.api.crud_helpers"

return {
  ["/consumers/:username_or_id/paseto/"] = {
    before = function(self, dao_factory, helpers)
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
      self.params.consumer_id = self.consumer.id
    end,

    GET = function(self, dao_factory)
      crud.paginated_set(self, dao_factory.paseto_keys)
    end,

    PUT = function(self, dao_factory)
      crud.put(self.params, dao_factory.paseto_keys)
    end,

    POST = function(self, dao_factory)
      crud.post(self.params, dao_factory.paseto_keys)
    end
  },
  ["/consumers/:username_or_id/paseto/:paseto_kid_or_id"] = {
    before = function(self, dao_factory, helpers)
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
      self.params.consumer_id = self.consumer.id

      local keys, err = crud.find_by_id_or_field(
        dao_factory.paseto_keys,
        { consumer_id = self.params.consumer_id },
        ngx.unescape_uri(self.params.paseto_kid_or_id),
        "kid"
      )

      if err then
        return helpers.yield_error(err)
      elseif next(keys) == nil then
        return helpers.responses.send_HTTP_NOT_FOUND()
      end
      self.params.paseto_kid_or_id = nil

      self.paseto_key = keys[1]
    end,

    GET = function(self, _, helpers)
      return helpers.responses.send_HTTP_OK(self.paseto_key)
    end,

    PATCH = function(self, dao_factory)
      crud.patch(self.params, dao_factory.paseto_keys, self.paseto_key)
    end,

    DELETE = function(self, dao_factory)
      crud.delete(self.paseto_key, dao_factory.paseto_keys)
    end
  },
  ["/pasetos/"] = {
    GET = function(self, dao_factory)
      crud.paginated_set(self, dao_factory.paseto_keys)
    end
  },
  ["/pasetos/:paseto_kid_or_id/consumer"] = {
    before = function(self, dao_factory, helpers)
      local keys, err = crud.find_by_id_or_field(
        dao_factory.paseto_keys,
        nil,
        ngx.unescape_uri(self.params.paseto_kid_or_id),
        "kid"
      )

      if err then
        return helpers.yield_error(err)
      elseif next(keys) == nil then
        return helpers.responses.send_HTTP_NOT_FOUND()
      end

      self.params.paseto_kid_or_id = nil
      self.params.username_or_id = keys[1].consumer_id
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
    end,

    GET = function(self, _, helpers)
      return helpers.responses.send_HTTP_OK(self.consumer)
    end
  }
}
