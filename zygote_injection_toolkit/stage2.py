import socket
import codecs
import re
import shlex
from typing import Any
from io import BytesIO
from warnings import warn
from pathlib import Path

# AIDL は使用しないためインポートを無効化
# import aidl

from .exceptions import *
from .parcel import *


def swap_endianness(bytes_: bytes) -> bytes:
    result = b""
    bytes_io = BytesIO(bytes_)
    while True:
        read_bytes = bytes_io.read(4)
        if not read_bytes:
            break
        result += read_bytes[::-1]
    return result


def parse_service_result(service_result: str) -> bytes:
    'decodes the raw response from the "service call" AOSP command line utility'
    EXPRESSION = re.compile(
        r"^(?:Result\: Parcel\(|  0x[0-9a-fA-F]+: )((?:[0-9a-fA-F ])+)'[^']*'\)?$"
    )

    matched_any = False
    result = b""
    for line in service_result.split("\n"):
        matched = EXPRESSION.fullmatch(line)
        if matched is None:
            continue
        matched_any = True
        result += codecs.decode(matched[1].replace(" ", ""), "hex")
    if not matched_any:
        raise ZygoteInjectionException("service call failed")
    return swap_endianness(result)


def parse_boolean_result(result: bytes) -> bool:
    status_code = int.from_bytes(result[:4], "little")
    if status_code:
        raise Exception("oh no!")
    number = int.from_bytes(result[4:8], "little")
    return bool(number)


# ===== AIDL 解析を完全にスキップ =====
# with open(Path(__file__).parent / "IOemLockService.aidl") as handle:
#     oem_lock_service_aidl = handle.read()
# oem_lock_service = parse_aidl_interface(
#     aidl.fromstring(oem_lock_service_aidl), "IOemLockService"
# )
# known_services = {"oem_lock": oem_lock_service}）
known_services = {}


class Stage2Exploit:
    def __init__(self, port: int = 1234) -> None:
        self.port = port

    def call_service(
        self,
        device_socket: socket.SocketType,
        service_name: str,
        function: str,
        *arguments: ParcelType
    ) -> ...:
        # すべての service call をスキップ（何も送信せず、常に None を返す）
        print(f"Skipping service call: {service_name}.{function}")
        return None

    def exploit_stage2(self):
        # ===== OEM アンロック関連の全処理をスキップ =====
        print("Skipping all OEM unlock processing (AIDL and service calls are disabled).")
        return

        



# Stage2Exploit().exploit_stage2()
# exit()
