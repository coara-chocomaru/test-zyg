#!/system/bin/sh
set +e

export TMPDIR=/cache/

base64 -d > /cache/command << 'B64EOF'
Ym9vdC1yZWNvdmVyeQotLXNpZGVsb2FkCi0tc2hvd190ZXh0Ci0tcmVhc29uPWtjcGVybWlzc2l2ZQotLWFkYmQKLS1yZXRyeV9jb3VudD0zCg==
B64EOF
