#!/bin/bash

luarocks install libsodium
luarocks make

cd /kong
make dev

export KONG_CUSTOM_PLUGINS=paseto

echo "custom_plugins = paseto" >> spec/kong_tests.conf

cp spec/kong_tests.conf spec/kong_tests_cassandra.conf
sed -i -e 's/database = postgres/database = cassandra/g' spec/kong_tests_cassandra.conf

bin/kong migrations up
bin/kong migrations up -c spec/kong_tests.conf
bin/kong migrations up -c spec/kong_tests_cassandra.conf

# Plugin tests can now be run
echo "Run plugin tests from /kong with:  bin/busted /kong-plugin/spec -v -o gtest"
