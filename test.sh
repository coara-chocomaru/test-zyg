#!/system/bin/sh
set +e

export TMPDIR=/cache/

base64 -d > /data/local.prop << 'B64EOF'
cm8ua2VybmVsLnFlbXU9MQpyby5zZWN1cmU9MAo=
B64EOF
