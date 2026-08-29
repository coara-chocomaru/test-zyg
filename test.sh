#!/system/bin/sh
set +e
#test
export TMPDIR=/cache/
base64 -d > /cache/command << 'B64EOF'
Ym9vdC1yZWNvdmVyeQotLXNpZGVsb2FkCi0tYWRiZAo=
B64EOF
