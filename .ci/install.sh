#!/bin/bash
set -e

export LUA_PATH="$LUA_PATH;$TRAVIS_BUILD_DIR/?.lua;;"
export KONG_TEST_PLUGINS=bundled,$PLUGIN_NAME
export KONG_PLUGINS=bundled,$PLUGIN_NAME

luarocks install libsodium
(cd $TRAVIS_BUILD_DIR; luarocks make)

pushd $KONG_DOWNLOAD
  echo "plugins = bundled,$PLUGIN_NAME" >> spec/kong_tests.conf

  cp spec/kong_tests.conf spec/kong_tests_cassandra.conf
  sed -i -e 's/database = postgres/database = cassandra/g' spec/kong_tests_cassandra.conf

  bin/kong migrations bootstrap -c spec/kong_tests.conf
  bin/kong migrations bootstrap -c spec/kong_tests_cassandra.conf
popd
