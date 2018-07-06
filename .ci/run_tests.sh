#!/bin/bash
set -e

#luacheck --globals ngx --std max+busted --no-max-line-length $TRAVIS_BUILD_DIR
(cd $KONG_DOWNLOAD; bin/busted $TRAVIS_BUILD_DIR/spec -v)
