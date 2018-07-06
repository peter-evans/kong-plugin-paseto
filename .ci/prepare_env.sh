#!/bin/bash
set -e

# Download dependencies to cache
OPENSSL_DOWNLOAD=$DOWNLOAD_CACHE/openssl-$OPENSSL
OPENRESTY_DOWNLOAD=$DOWNLOAD_CACHE/openresty-$OPENRESTY
LUAROCKS_DOWNLOAD=$DOWNLOAD_CACHE/luarocks-$LUAROCKS
export KONG_DOWNLOAD=$DOWNLOAD_CACHE/kong-$KONG

if [ ! "$(ls -A $OPENSSL_DOWNLOAD)" ]; then
  pushd $DOWNLOAD_CACHE
    curl -s -S -L http://www.openssl.org/source/openssl-$OPENSSL.tar.gz | tar xz
  popd
fi

if [ ! "$(ls -A $OPENRESTY_DOWNLOAD)" ]; then
  pushd $DOWNLOAD_CACHE
    curl -s -S -L https://openresty.org/download/openresty-$OPENRESTY.tar.gz | tar xz
  popd
fi

if [ ! "$(ls -A $LUAROCKS_DOWNLOAD)" ]; then
  git clone -q https://github.com/keplerproject/luarocks.git $LUAROCKS_DOWNLOAD
fi

if [ ! "$(ls -A $KONG_DOWNLOAD)" ]; then
  git clone -q https://github.com/Kong/kong.git $KONG_DOWNLOAD
fi

OPENSSL_INSTALL=$INSTALL_CACHE/openssl-$OPENSSL
OPENRESTY_INSTALL=$INSTALL_CACHE/openresty-$OPENRESTY
LUAROCKS_INSTALL=$INSTALL_CACHE/luarocks-$LUAROCKS

mkdir -p $OPENSSL_INSTALL $OPENRESTY_INSTALL $LUAROCKS_INSTALL

# Install OpenSSL
if [ ! "$(ls -A $OPENSSL_INSTALL)" ]; then
  pushd $OPENSSL_DOWNLOAD
    ./config shared --prefix=$OPENSSL_INSTALL &> build.log || (cat build.log && exit 1)
    make &> build.log || (cat build.log && exit 1)
    make install &> build.log || (cat build.log && exit 1)
  popd
fi

# Install OpenResty
if [ ! "$(ls -A $OPENRESTY_INSTALL)" ]; then
  OPENRESTY_OPTS=(
    "--prefix=$OPENRESTY_INSTALL"
    "--with-openssl=$OPENSSL_DOWNLOAD"
    "--with-ipv6"
    "--with-pcre-jit"
    "--with-http_ssl_module"
    "--with-http_realip_module"
    "--with-http_stub_status_module"
    "--with-http_v2_module"
  )

  pushd $OPENRESTY_DOWNLOAD
    ./configure ${OPENRESTY_OPTS[*]} &> build.log || (cat build.log && exit 1)
    make &> build.log || (cat build.log && exit 1)
    make install &> build.log || (cat build.log && exit 1)
  popd
fi

# Install Luarocks
if [ ! "$(ls -A $LUAROCKS_INSTALL)" ]; then
  pushd $LUAROCKS_DOWNLOAD
    git checkout -q v$LUAROCKS
    ./configure \
      --prefix=$LUAROCKS_INSTALL \
      --lua-suffix=jit \
      --with-lua=$OPENRESTY_INSTALL/luajit \
      --with-lua-include=$OPENRESTY_INSTALL/luajit/include/luajit-2.1 \
      &> build.log || (cat build.log && exit 1)
    make build &> build.log || (cat build.log && exit 1)
    make install &> build.log || (cat build.log && exit 1)
  popd
fi
export OPENSSL_DIR=$OPENSSL_INSTALL
export PATH=$PATH:$OPENRESTY_INSTALL/nginx/sbin:$OPENRESTY_INSTALL/bin:$LUAROCKS_INSTALL/bin

eval `luarocks path`

nginx -V
resty -V
luarocks --version

# Checkout Kong and make dev environment
pushd $KONG_DOWNLOAD
  git checkout -q $KONG
  make dev &> build.log || (cat build.log && exit 1)
popd

# Install luacov
luarocks install luacov
luarocks install luacov-coveralls

# Create postgres user and database
psql -U postgres <<EOF
\x
CREATE USER kong;
CREATE DATABASE kong_tests OWNER kong;
EOF
