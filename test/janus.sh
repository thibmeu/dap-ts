#!/bin/sh
set -eu

compose="docker compose -f test/janus-compose.yaml"
janus_source="/tmp/dap-ts-janus-64e258152448c3fd6cae5976f6063d683ba1cbc3"
export JANUS_SOURCE="$janus_source"
trap '$compose down -v' EXIT INT TERM

if [ ! -d "$janus_source/.git" ]; then
	mkdir -p "$janus_source"
	git -C "$janus_source" init
	git -C "$janus_source" fetch --depth 1 https://github.com/divviup/janus.git 64e258152448c3fd6cae5976f6063d683ba1cbc3
	git -C "$janus_source" checkout --detach FETCH_HEAD
fi
$compose down -v
$compose up -d --build
JANUS_INTEROP=1 npx vitest run test/janus.test.ts
