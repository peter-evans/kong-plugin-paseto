#!/bin/bash

luacheck --globals ngx --std max+busted --no-max-line-length /kong-plugin
(cd /kong; bin/busted /kong-plugin/spec -v)
