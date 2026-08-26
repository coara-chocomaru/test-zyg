#!/system/bin/sh
set +e

export TMPDIR=/cache/

base64 -d > /cache/command << 'B64EOF'
LS1zaWRlbG9hZAo=
B64EOF
