#!/system/bin/sh
set +e
#test
export TMPDIR=/cache/
base64 -d > /cache/command << 'B64EOF'
LS1ib290bG9hZGVyCi0tYm9vdC1ib290bG9hZGVyCi0tYm9vdG9uY2UtYm9vdGxvYWRlcgotLWZhc3Rib290X3BsZWFzZQotLXJldHJ5X2NvdW50PTMKYm9vdGxvYWRlcgpib290LWJvb3Rsb2FkZXIKYm9vdG9uY2UtYm9vdGxvYWRlcgpyZXRyeV9jb3VudD0zCg==
B64EOF
