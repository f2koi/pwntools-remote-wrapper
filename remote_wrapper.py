from socket import socket
from ssl import SSLContext
from typing import Any, Dict, Literal

from pwn import remote as __remote, process as __process


class Remote(__remote):
    def __init__(
        self,
        host: str,
        port: int,
        fam: int | Literal["any"] | Literal["ipv4"] | Literal["ipv6"] = "ipv4",
        typ: int | Literal["tcp"] | Literal["udp"] = "tcp",
        ssl: bool = False,
        sock: socket | None = None,
        ssl_context: SSLContext | None = None,
        ssl_args: Dict[str, Any] | None = None,
        sni: bool = True,
    ):
        super().__init__(host, port, fam, typ, ssl, sock, ssl_context, ssl_args, sni)  # type: ignore

    def recvuntil(
        self, delimeter: bytes, drop: bool = False, timeout: int = 5
    ) -> bytes:
        return super().recvuntil(delimeter, drop, timeout)

    def recvn(self, n: int, timeout: int = 5) -> bytes:
        return super().recvn(n, timeout)

    def sendlineafter(self, delimeter: bytes, data: bytes, timeout: int = 5) -> bytes:
        return super().sendlineafter(delimeter, data, timeout)

    def send(self, data: bytes):
        super().send(data)

    def interactive(self):
        super().interactive()


class Process(__process):
    def __init__(
        self,
        argv=None,
        env=None,
        aslr=None,
        cwd=None,
        executable=None,
        shell=False,
        **kwargs
    ):
        super().__init__(  # type: ignore
            argv=argv,
            env=env,
            aslr=aslr,
            cwd=cwd,
            executable=executable,
            shell=shell,
            **kwargs,
        )  # type: ignore

    def recvuntil(
        self, delimeter: bytes, drop: bool = False, timeout: int = 1
    ) -> bytes:
        return super().recvuntil(delimeter, drop, timeout)

    def recvn(self, n: int, timeout: int = 1) -> bytes:
        return super().recvn(n, timeout)

    def sendlineafter(self, delimeter: bytes, data: bytes, timeout: int = 1) -> bytes:
        return super().sendlineafter(delimeter, data, timeout)

    def send(self, data: bytes):
        super().send(data)

    def interactive(self):
        super().interactive()
