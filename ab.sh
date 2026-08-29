#!/bin/bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "使い方: $0 <input.ab> [output.tar]"
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-${INPUT%.ab}.tar}"
OUTPUT="${OUTPUT%.AB}.tar"

if [[ ! -f "$INPUT" ]]; then
    echo "エラー: $INPUT が見つかりません"
    exit 1
fi

if [[ -e "$OUTPUT" ]]; then
    echo "エラー: $OUTPUT が既に存在します"
    exit 1
fi

# Pythonでヘッダを正しく読み飛ばして展開
python3 - "$INPUT" "$OUTPUT" << 'EOF'
import sys
import zlib

infile = sys.argv[1]
outfile = sys.argv[2]

with open(infile, "rb") as f:
    # ヘッダを1行ずつ読む
    magic = f.readline()
    if not magic.startswith(b"ANDROID BACKUP"):
        print("エラー: ANDROID BACKUP ヘッダが見つかりません")
        sys.exit(1)

    version = f.readline().strip()
    compressed = f.readline().strip()   # b'1' or b'0'
    encryption = f.readline().strip()   # b'none' or b'AES-256'

    print(f"Version   : {version.decode()}")
    print(f"Compressed: {compressed.decode()}")
    print(f"Encryption: {encryption.decode()}")

    if encryption != b"none":
        print("\nこのバックアップは暗号化されています。")
        print("パスワード付きの場合は Android Backup Extractor (abe.jar) を使ってください。")
        print("  java -jar abe.jar unpack backup.ab backup.tar パスワード")
        sys.exit(1)

    data = f.read()

if compressed == b"1":
    try:
        # zlib形式で展開
        tar_data = zlib.decompress(data)
    except zlib.error as e:
        print(f"zlib展開に失敗: {e}")
        print("バックアップファイルが壊れている可能性があります。")
        sys.exit(1)
else:
    tar_data = data  # 非圧縮

with open(outfile, "wb") as out:
    out.write(tar_data)

print(f"\n成功: {outfile} を作成しました")
print(f"サイズ: {len(tar_data):,} bytes")
EOF
