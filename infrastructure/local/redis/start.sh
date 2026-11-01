#!/bin/sh
set -eu
: "${FCB_REDIS_PASSWORD:?Bootstrap local credentials before starting Redis}"
umask 077
printf 'bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nmaxmemory 128mb\nmaxmemory-policy noeviction\nrequirepass %s\n' "$FCB_REDIS_PASSWORD" > /tmp/redis.conf
exec redis-server /tmp/redis.conf
