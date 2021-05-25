#!/bin/sh

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

export NGINX_VERSION=1.17.7
export NDK_VERSION=0.3.1rc1
export VTS_VERSION=0.1.15
export SETMISC_VERSION=0.32
export LUA_VERSION=0.10.13
export STICKY_SESSIONS_VERSION=08a395c66e42
export LUA_CJSON_VERSION=2.1.0.7
export LUA_RESTY_HTTP_VERSION=0.07
export LUA_UPSTREAM_VERSION=0.07
export MORE_HEADERS_VERSION=0.33
export ENCRYPTED_SESSION_VERSION=0.08
export STATSD_VERSION=0.0.1

export NGINX_DIGEST_AUTH=7955af9c77598c697ac292811914ce1e2b3b824c
export NGINX_SUBSTITUTIONS=bc58cb11844bc42735bbaef7085ea86ace46d05b

export BUILD_PATH=/tmp/build

get_src()
{
  hash="$1"
  url="$2"
  f=$(basename "$url")

  curl -H "X-JFrog-Art-Api:${ARTIFACTORY_API_KEY}" -L -o "$f" "$url"
  echo "$hash  $f" | sha256sum -c - || exit 10
  tar xzf "$f"
  rm -rf "$f"
}

mkdir "$BUILD_PATH"
cd "$BUILD_PATH"

# install required packages to build
apt-get update && apt-get -y upgrade && apt-get install --fix-missing && apt-get install --no-install-recommends -y && apt-get dist-upgrade -y \
  build-essential \
  libgeoip1 \
  libgeoip-dev \
  patch \
  libpcre3 \
  libpcre3-dev \
  libssl-dev \
  zlib1g \
  zlib1g-dev \
  libaio1 \
  libaio-dev \
  luajit \
  openssl \
  libluajit-5.1 \
  libluajit-5.1-dev \
  liblua5.1-0 \
  liblua5.1-0-dev \
  lua-cjson-dev \
  curl \
  linux-headers-generic || exit 1

# download, verify and extract the source files
get_src b62756842807e5693b794e5d0ae289bd8ae5b098e66538b2a91eb80f25c591ff \
        "${NGINX_LINK}/nginx-$NGINX_VERSION.tar.gz"

get_src 49f50d4cd62b166bc1aaf712febec5e028d9f187cedbc27a610dfd01bdde2d36 \
        "${GH_LINK}/simpl/ngx_devel_kit/archive/v$NDK_VERSION.tar.gz"

get_src f1ad2459c4ee6a61771aa84f77871f4bfe42943a4aa4c30c62ba3f981f52c201 \
        "${GH_LINK}/openresty/set-misc-nginx-module/archive/v$SETMISC_VERSION.tar.gz"

get_src 5112a054b1b1edb4c0042a9a840ef45f22abb3c05c68174e28ebf483164fb7e1 \
        "${GH_LINK}/vozlt/nginx-module-vts/archive/v$VTS_VERSION.tar.gz"

get_src ecea8c3d7f69dd48c6132498ddefb5d83ba9f387fa3d4da14e2abeacdfc8a3ee \
        "${GH_LINK}/openresty/lua-nginx-module/archive/v$LUA_VERSION.tar.gz"

get_src 59d2f18ecadba48be61061004c8664eaed1111a3372cd2567cb24c5a47eb41fe \
        "${GH_LINK}/openresty/lua-cjson/archive/$LUA_CJSON_VERSION.tar.gz"

get_src 1c6aa06c9955397c94e9c3e0c0fba4e2704e85bee77b4512fb54ae7c25d58d86 \
        "${GH_LINK}/pintsized/lua-resty-http/archive/v$LUA_RESTY_HTTP_VERSION.tar.gz"

get_src a3dcbab117a9c103bc1ea5200fc00a7b7d2af97ff7fd525f16f8ac2632e30fbf \
        "${GH_LINK}/openresty/headers-more-nginx-module/archive/v$MORE_HEADERS_VERSION.tar.gz"

get_src 2a69815e4ae01aa8b170941a8e1a10b6f6a9aab699dee485d58f021dd933829a \
        "${GH_LINK}/openresty/lua-upstream-nginx-module/archive/v$LUA_UPSTREAM_VERSION.tar.gz"

get_src 53e440737ed1aff1f09fae150219a45f16add0c8d6e84546cb7d80f73ebffd90 \
        "${NGINX_GOODIES_LINK}/get/$STICKY_SESSIONS_VERSION.tar.gz"

get_src 9b1d0075df787338bb607f14925886249bda60b6b3156713923d5d59e99a708b \
        "${GH_LINK}/atomx/nginx-http-auth-digest/archive/$NGINX_DIGEST_AUTH.tar.gz"

get_src 618551948ab14cac51d6e4ad00452312c7b09938f59ebff4f93875013be31f2d \
        "${GH_LINK}/yaoweibin/ngx_http_substitutions_filter_module/archive/$NGINX_SUBSTITUTIONS.tar.gz"

get_src 6e526ea097c6805ec2cf1d0d3d79ed24326bc2d0babe158c29edd07d8c0d106a \
        "${GH_LINK}/openresty/encrypted-session-nginx-module/archive/v$ENCRYPTED_SESSION_VERSION.tar.gz"

get_src 8e05f880e4fd60862f8b3f58cedf14e64b2c7833c6693d830651b383af2baf45 \
        "${GH_LINK}/zebrafishlabs/nginx-statsd/archive/$STATSD_VERSION.tar.gz"

# build nginx
cd "$BUILD_PATH/nginx-$NGINX_VERSION"

cp /tmp/nginx-controller/patches/ngx_resolver_c.diff ${BUILD_PATH}/nginx-${NGINX_VERSION}/ngx_resolver_c.diff
cp /tmp/nginx-controller/patches/ngx_resolver_h.diff ${BUILD_PATH}/nginx-${NGINX_VERSION}/ngx_resolver_h.diff

# patch the statsd module
patch -p1 < ./ngx_resolver_c.diff
patch -p1 < ./ngx_resolver_h.diff

./configure \
  --prefix=/usr/share/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --lock-path=/var/lock/nginx.lock \
  --pid-path=/run/nginx.pid \
  --http-client-body-temp-path=/var/lib/nginx/body \
  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
  --http-proxy-temp-path=/var/lib/nginx/proxy \
  --http-scgi-temp-path=/var/lib/nginx/scgi \
  --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
  --with-debug \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-http_auth_request_module \
  --with-http_addition_module \
  --with-http_dav_module \
  --with-http_geoip_module \
  --with-http_gzip_static_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-threads \
  --with-file-aio \
  --without-mail_pop3_module \
  --without-mail_smtp_module \
  --without-mail_imap_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' \
  --add-module="$BUILD_PATH/ngx_devel_kit-$NDK_VERSION" \
  --add-module="$BUILD_PATH/set-misc-nginx-module-$SETMISC_VERSION" \
  --add-module="$BUILD_PATH/nginx-module-vts-$VTS_VERSION" \
  --add-module="$BUILD_PATH/lua-nginx-module-$LUA_VERSION" \
  --add-module="$BUILD_PATH/headers-more-nginx-module-$MORE_HEADERS_VERSION" \
  --add-module="$BUILD_PATH/nginx-goodies-nginx-sticky-module-ng-$STICKY_SESSIONS_VERSION" \
  --add-module="$BUILD_PATH/nginx-http-auth-digest-$NGINX_DIGEST_AUTH" \
  --add-module="$BUILD_PATH/ngx_http_substitutions_filter_module-$NGINX_SUBSTITUTIONS" \
  --add-module="$BUILD_PATH/encrypted-session-nginx-module-$ENCRYPTED_SESSION_VERSION" \
  --add-module="$BUILD_PATH/nginx-statsd-$STATSD_VERSION" \
  --add-module="$BUILD_PATH/lua-upstream-nginx-module-$LUA_UPSTREAM_VERSION" || exit 1 \
  && make || exit 1 \
  && make install || exit 1

echo "Installing CJSON module"
cd "$BUILD_PATH/lua-cjson-$LUA_CJSON_VERSION"
make LUA_INCLUDE_DIR=/usr/include/luajit-2.1 && make install

echo "Installing lua-resty-http module"
# copy lua module
cd "$BUILD_PATH/lua-resty-http-$LUA_RESTY_HTTP_VERSION"
sed -i 's/resty.http_headers/http_headers/' $BUILD_PATH/lua-resty-http-$LUA_RESTY_HTTP_VERSION/lib/resty/http.lua
cp $BUILD_PATH/lua-resty-http-$LUA_RESTY_HTTP_VERSION/lib/resty/http.lua /usr/local/lib/lua/5.1
cp $BUILD_PATH/lua-resty-http-$LUA_RESTY_HTTP_VERSION/lib/resty/http_headers.lua /usr/local/lib/lua/5.1

echo "Cleaning..."

cd /

apt-mark unmarkauto \
  libgeoip1 \
  libpcre3 \
  zlib1g \
  libaio1 \
  luajit \
  libluajit-5.1-2 \
  xz-utils \
  geoip-bin \
  openssl

apt-get remove -y --purge \
  build-essential \
  gcc-5 \
  cpp-5 \
  libgeoip-dev \
  libpcre3-dev \
  libssl-dev \
  zlib1g-dev \
  libaio-dev \
  libluajit-5.1-dev \
  linux-libc-dev \
  liblua5.1-0-dev \
  perl-modules-5.26 \
  linux-headers-generic

apt-get autoremove -y

mkdir -p /var/lib/nginx/body /usr/share/nginx/html
mkdir -p /usr/share/nginx/xml
mkdir -p /etc/nginx/conf.d/
mkdir -p /etc/nginx/streamconf.d/
mkdir -p /var/log/nginx/activitytracker
mkdir -p /var/log/nginx/customerlogs

adduser --system --no-create-home --shell /bin/false --group --disabled-login nginx

mv /usr/share/nginx/sbin/nginx /usr/sbin

rm -rf "$BUILD_PATH"
rm -Rf /usr/share/man /usr/share/doc
rm -rf /var/lib/apt/lists/*
rm -rf /var/cache/apt/archives/*

# move root CA certs to correct location
update-ca-certificates
cp /usr/share/ca-certificates/mozilla/* /usr/local/share/ca-certificates/

# Download of GeoIP databases
# Disabled temporarily while we figure out what we should with the new license
#wget -nv "https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz" -O /etc/nginx/GeoIP.dat.gz \
#  && wget -nv "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz" -O /etc/nginx/GeoLiteCity.dat.gz \
#  && gunzip -f /etc/nginx/GeoIP.dat.gz \
#  && gunzip -f /etc/nginx/GeoLiteCity.dat.gz

# overwrite default insecure nginx.conf with one that satisfies vulnerability advisor
cat >/etc/nginx/nginx.conf <<EOF
# dummy nginx.conf, replaced at runtime by nginx.conf.tmpl templating
user nginx;
http {
  server_tokens off;
  ssl_prefer_server_ciphers on;
  server {
    listen 8443 ssl default_server;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/nginx/snakeoil.crt;
    ssl_certificate_key /etc/nginx/snakeoil.key;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
    location / {
      return 404;
    }
  }
}
EOF

apt-get remove -y --allow-remove-essential --purge bash