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
    def __init__(self, root_dns_ip: str, port: int) -> None:
        self._root_dns_ip: str = root_dns_ip
        self._port: int = port
        self._logger: Logger = logging.getLogger(__name__)
        self._resolver: Resolver = Resolver(self._logger, self._root_dns_ip)

    async def start_handling(self) -> None:
        self._logger.info(
            f"Старт DNS сервера ip: 127.0.0.1 port: {self._port} ..."
        )
        async with TaskGroup() as tg:
            tg.create_task(self._start_tcp_server())
            tg.create_task(self._handle_udp_client())

    async def _start_tcp_server(self) -> None:
        server = await asyncio.start_server(
            self._handle_tcp_client, host=None, port=self._port
        )
        async with server:
            await server.serve_forever()

    async def _handle_udp_client(self):
        loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        sock_udp: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_udp.setblocking(False)
        sock_udp.bind(("0.0.0.0", self._port))

        try:
            while True:
                raw_client_query, addr = await loop.sock_recvfrom(sock_udp, 1024)
                self._logger.info(f"(UDP) Получено сообщение от {addr}")
                try:
                    result: bytes = await self._get_dns_response(
                        raw_client_query, use_tcp=False
                    )
                except message.MessageError:
                    continue

                await loop.sock_sendto(sock_udp, result, addr)
        finally:
            sock_udp.close()

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client_addr: str = str(writer.get_extra_info("peername"))
        self._logger.info(f"(TCP) Обрабатывается {client_addr}")
        message_length_in_bytes: bytes = await reader.readexactly(2)
        message_length: int = int.from_bytes(message_length_in_bytes, byteorder="big")
        dns_client_query_raw: bytes = await reader.read(message_length)
        self._logger.info(f"(TCP) Получено сообщение от {client_addr}")
        try:
            raw_dns_response: bytes = await self._get_dns_response(
                dns_client_query_raw, use_tcp=True
            )
        except message.MessageError:
            return
        writer.write(int.to_bytes(len(raw_dns_response), 2, byteorder="big"))
        writer.write(raw_dns_response)

        await writer.drain()

    async def _get_dns_response(self, raw_query: bytes, use_tcp: bool = False) -> bytes:
        try:
            dns_client_query: message.Message = dns.message.from_wire(raw_query)
            dns_client_query.flags &= ~dns.flags.RD
        except message.MessageError:
            self._logger.error(
                "Возбуждено исключение во время парсинга DNS сообщения"
            )
            raise

        answer_message: Message | None = await self._resolver.resolve(
            dns_client_query,
            self._root_dns_ip,
            dns_client_query.question[0].name.to_text(omit_final_dot=True),
            use_tcp=use_tcp,
        )
        if answer_message is None:
            nxdomain_message: Message = dns.message.make_response(dns_client_query)
            nxdomain_message.set_rcode(dns.rcode.NXDOMAIN)
            nxdomain_message.flags |= dns.flags.RA
            return nxdomain_message.to_wire()
        else:
            answer_message.flags |= dns.flags.RA
            wire_response: bytes = answer_message.to_wire()
            return wire_response
