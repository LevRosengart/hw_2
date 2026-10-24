import asyncio
import logging
import socket

import dns
import dns.message as message
from dns.message import Message
from asyncio import TaskGroup
from logging import Logger
from .resolver import Resolver


class DnsServer:
    ROOT_DNS_IP: str = "199.7.83.42"
    MY_SERVER_PORT: int = 5553

    def __init__(self) -> None:
        self._logger: Logger = logging.getLogger(__name__)
        self._my_server_ip: str = self._get_local_ip()
        self._resolver: Resolver = Resolver(self._logger)

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client_addr: str = str(writer.get_extra_info("peername"))
        self._logger.info(f"Handling {client_addr}")
        message_length_in_bytes: bytes = await reader.readexactly(2)
        message_length: int = int.from_bytes(message_length_in_bytes, byteorder="big")
        dns_client_query_raw: bytes = await reader.read(message_length)
        self._logger.info(f"Received message from {client_addr}")
        try:
            dns_client_query: Message = dns.message.from_wire(dns_client_query_raw)
        except message.MessageError:
            self._logger.error(
                "Raised error while parsing dns message from client (with TCP)"
            )
            return

        dns_answer_bytes: Message = await self._resolver.resolve(
            dns_client_query, self.ROOT_DNS_IP
        )
        wire_response: bytes = dns_answer_bytes.to_wire()
        writer.write(int.to_bytes(len(wire_response), 2, byteorder="big"))
        writer.write(wire_response)

        await writer.drain()

    async def _handle_udp_client(self):
        loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

        sock_udp: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_udp.setblocking(False)
        sock_udp.bind(("0.0.0.0", self.MY_SERVER_PORT))

        try:
            while True:
                data, addr = await loop.sock_recvfrom(sock_udp, 1024)
                self._logger.info(f"Received message from {addr}")

                try:
                    dns_client_query: message.Message = dns.message.from_wire(data)
                except message.MessageError:
                    self._logger.error(
                        "Raised error while parsing dns message from client (with UDP)"
                    )
                    continue

                answer_message: Message = await self._resolver.resolve(
                    dns_client_query, self.ROOT_DNS_IP
                )

                wire_response: bytes = answer_message.to_wire()
                await loop.sock_sendto(sock_udp, wire_response, addr)
        finally:
            sock_udp.close()

    def _get_local_ip(self) -> str:
        sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            local_ip: str = sock.getsockname()[0]
        except Exception:  # noqa
            self._logger.error("Raised unexpected exception while resolving local ip")
            local_ip: str = "127.0.0.1"
        finally:
            sock.close()
        return local_ip

    async def _start_tcp_server(self) -> None:
        server = await asyncio.start_server(
            self._handle_tcp_client, host=None, port=self.MY_SERVER_PORT
        )
        async with server:
            await server.serve_forever()

    async def start_handling(self) -> None:
        self._logger.info(f"Starting DNS server on {self._my_server_ip}...")
        async with TaskGroup() as tg:
            tg.create_task(self._start_tcp_server())
            tg.create_task(self._handle_udp_client())
