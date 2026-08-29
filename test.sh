#!/system/bin/sh
set +e
#test
export TMPDIR=/cache/
base64 -d > /cache/command << 'B64EOF'
Ym9vdC1yZWNvdmVyeQotLWJvb3Rsb2FkZXIKLS1ib290LWJvb3Rsb2FkZXIKLS1ib290b25jZS1ib290bG9hZGVyCi0tZmFzdGJvb3RfcGxlYXNlCi0tcmV0cnlfY291bnQ9Mwpib290bG9hZGVyCmJvb3QtYm9vdGxvYWRlcgpib290b25jZS1ib290bG9hZGVyCnJldHJ5X2NvdW50PTMK
B64EOF
