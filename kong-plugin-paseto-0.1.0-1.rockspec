package = "kong-plugin-paseto"
version = "0.1.0-1"
description = {
  summary = "Kong plugin for PASETO (Platform-Agnostic Security Tokens)",
  detailed = "PASETO (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation for secure stateless tokens.",
  homepage = "http://github.com/peter-evans/kong-plugin-paseto",
  license = "MIT"
}
source = {
  url = "git://github.com/peter-evans/kong-plugin-paseto",
  tag = "0.1.0"
}
dependencies = {
  "paseto >= 0.1.0"
}
supported_platforms = {
  "linux", 
  "macosx"
}
local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "paseto"
build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..pluginName..".handler"] = "kong/plugins/"..pluginName.."/handler.lua",
    ["kong.plugins."..pluginName..".schema"] = "kong/plugins/"..pluginName.."/schema.lua",
  }
}
