#!/bin/bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "使い方: $0 <input.ab> [output.tar]"
    echo "例:    $0 mybackup.ab"
    echo "      $0 mybackup.ab mybackup.tar"
    exit 1
fi

INPUT="$1"
if [[ ! -f "$INPUT" ]]; then
    echo "エラー: ファイルが見つかりません: $INPUT"
    exit 1
fi

# 出力ファイル名
if [[ $# -ge 2 ]]; then
    OUTPUT="$2"
else
    OUTPUT="${INPUT%.ab}.tar"
    OUTPUT="${OUTPUT%.AB}.tar"  # 大文字対応
fi

if [[ -e "$OUTPUT" ]]; then
    echo "エラー: 出力ファイルが既に存在します: $OUTPUT"
    exit 1
fi

# zlib展開コマンドを選択
if command -v openssl >/dev/null 2>&1 && openssl zlib -d </dev/null >/dev/null 2>&1; then
    UNZLIB="openssl zlib -d"
elif command -v zlib-flate >/dev/null 2>&1; then
    UNZLIB="zlib-flate -uncompress"
else
    echo "エラー: openssl (zlib対応) または zlib-flate (qpdfパッケージ) が必要です"
    echo "インストール例:"
    echo "  sudo apt install openssl"
    echo "  または"
    echo "  sudo apt install qpdf"
    exit 1
fi

echo "変換中: $INPUT → $OUTPUT"
dd if="$INPUT" bs=24 skip=1 status=none | $UNZLIB > "$OUTPUT"

echo "完了: $OUTPUT"
ls -lh "$OUTPUT"
