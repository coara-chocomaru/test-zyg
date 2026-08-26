#!/system/bin/sh
set +e

export TMPDIR=/cache/

base64 -d > /cache/command << 'B64EOF'
Ym9vdC1yZWNvdmVyeQotLXNpZGVsb2FkCi0tcmV0cnlfY291bnQ9Mwo=
B64EOF
