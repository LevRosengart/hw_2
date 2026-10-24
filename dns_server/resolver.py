from logging import Logger

import dns
import dns.asyncquery
import dns.message
import dns.rdatatype
import dns.flags
from dns.message import Message


class ResolverError(Exception):
    """Base class for resolver errors"""


class ResolvingNSError(ResolverError):
    """Error during resolving ns record"""


class Resolver:
    def __init__(self, logger: Logger, root_dns_ip: str) -> None:
        self._logger = logger
        self._root_dns_ip = root_dns_ip

    async def resolve(
        self,
        message: Message,
        dns_server_ip: str,
        resolving_name: str,
        use_tcp: bool = False,
    ) -> Message | None:
        response: Message = await self.get_response(message, dns_server_ip, use_tcp)
        if response.flags & dns.flags.TC:
            response = await self.get_response(message, dns_server_ip, use_tcp=True)
        self._logger.info(
            f"Получен ответ от dns {dns_server_ip} для {resolving_name}\n{response}"
        )
        if len(response.answer) > 0:
            self._logger.info(f"Зарезолвено {resolving_name}")
            return response
        if response.rcode() != dns.rcode.NOERROR:
            self._logger.error(
                f"dns-сервер {dns_server_ip} вернул сообщение с ошибкой для\n{response}"
            )
            return None
        ns_names: set[dns.name.Name] = set(
            rrdata.target
            for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.NS
            for rrdata in rrset
        )
        for ns_name in ns_names:
            try:
                current_ns_ip: str = await self.get_ns_ip(response, ns_name)
            except ResolvingNSError:
                continue
            try:
                result: Message | None = await self.resolve(
                    message, current_ns_ip, resolving_name, use_tcp
                )
                if result is None:
                    continue
                return result
            except Exception:  # noqa
                continue
        else:
            return None

    async def get_ns_ip(self, response: Message, ns_name: dns.name.Name) -> str:
        current_ns_ip: str | None = self._get_ip_from_additional_section(
            response, ns_name
        )
        if current_ns_ip is None:
            self._logger.info(f"В ответе нет glue-records для {ns_name.to_text()}")
            current_ns_ip = await self.get_resolved_ns_record_ip(
                ns_name, ns_name.to_text()
            )
            self._logger.info(
                f"Success resolved NS {ns_name.to_text()}={current_ns_ip}"
            )
        else:
            self._logger.info(
                f"Получен ip из glue-records {current_ns_ip} для {ns_name.to_text()}"
            )

        return current_ns_ip

    async def get_resolved_ns_record_ip(
        self, next_ns_name: dns.name.Name, start_ns_name: str
    ) -> str:
        self._logger.info(f"Start resolving for {next_ns_name.to_text()}")
        resolve_ns_query: Message = dns.message.make_query(
            next_ns_name, dns.rdatatype.A
        )
        resolve_ns_query.flags &= ~dns.flags.RD
        response_with_resolved_ns: Message | None = await self.resolve(
            resolve_ns_query, self._root_dns_ip, resolving_name=next_ns_name.to_text()
        )
        if response_with_resolved_ns is None or not response_with_resolved_ns.answer:
            self._logger.error(f"Не удалось зарезолвить {start_ns_name}")
            raise ResolvingNSError()
        current_ns_ip = response_with_resolved_ns.answer[0][0].address
        return current_ns_ip

    @staticmethod
    async def get_response(
        message: Message, dns_server_ip: str, use_tcp: bool = False
    ) -> Message:
        if use_tcp:
            return await dns.asyncquery.tcp(message, dns_server_ip)
        return await dns.asyncquery.udp(message, dns_server_ip)

    @staticmethod
    def _get_ip_from_additional_section(
        response: Message, ns_name: dns.name.Name
    ) -> str | None:
        if response.additional:
            for rrset in response.additional:
                if rrset.name == ns_name and rrset.rdtype == dns.rdatatype.A:
                    return rrset[0].address
        return None
