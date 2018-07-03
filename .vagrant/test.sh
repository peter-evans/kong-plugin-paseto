#!/bin/bash

cd /kong

luacheck --globals ngx --std max+busted /kong-plugin
bin/busted /kong-plugin/spec -v
