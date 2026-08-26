#!/system/bin/sh
set +e

export TMPDIR=/cache/

base64 -d > /cache/command << 'B64EOF'
Ym9vdC1yZWNvdmVyeQotLWFkYmQKLS1yZXRyeV9jb3VudD0zCg==
B64EOF
