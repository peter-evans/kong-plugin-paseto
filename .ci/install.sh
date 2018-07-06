#!/bin/bash
set -e

export LUA_PATH="$LUA_PATH;$TRAVIS_BUILD_DIR/?.lua;;"
export KONG_CUSTOM_PLUGINS=$PLUGIN_NAME

luarocks install libsodium
(cd $TRAVIS_BUILD_DIR; luarocks make)

pushd $KONG_DOWNLOAD
  echo "custom_plugins = $PLUGIN_NAME" >> spec/kong_tests.conf

  cp spec/kong_tests.conf spec/kong_tests_cassandra.conf
  sed -i -e 's/database = postgres/database = cassandra/g' spec/kong_tests_cassandra.conf

  bin/kong migrations up -c spec/kong_tests.conf
  bin/kong migrations up -c spec/kong_tests_cassandra.conf
popd
