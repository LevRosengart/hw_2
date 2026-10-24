from logging import Logger
import dns
import dns.asyncquery
import dns.message
import dns.rdatatype
import dns.flags
from dns.message import Message


class Resolver:
    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    async def resolve(
        self,
        message: Message,
        dns_server_ip: str,
        use_tcp: bool = False,
        max_depth: int = 30,
    ) -> Message:

        if use_tcp:
            response: Message = await dns.asyncquery.tcp(message, dns_server_ip)
        else:
            response: Message = await dns.asyncquery.udp(message, dns_server_ip)
        self._logger.info(f"Получен ответ от dns {response}")
        if len(response.answer) > 0 or response.rcode() != dns.rcode.NOERROR:
            if response.rcode() != dns.rcode.NOERROR:
                self._logger.error(f"Ошибка dns сервера")
            else:
                self._logger.info(f"Зарезолвено")
            return response

        ns_names: set[dns.name.Name] = set(
            rdata.target
            for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.NS
            for rdata in rrset
        )

        for ns_name in ns_names:
            current_ns_ip: str | None = self._get_ip_from_additional_section(
                response, ns_name
            )
            self._logger.info(
                f"Получен ip из glue-records {current_ns_ip} для {ns_name}"
            )
            try:
                if current_ns_ip is not None:
                    return await self.resolve(
                        message, current_ns_ip, use_tcp, max_depth - 1
                    )
            except Exception:  # noqa
                continue

        self._logger.info("No glue-records found")
        return response

    @staticmethod
    def _get_ip_from_additional_section(
        response: Message, ns_name: dns.name.Name
    ) -> str | None:
        if response.additional:
            for rrset in response.additional:
                if rrset.name == ns_name and rrset.rdtype == dns.rdatatype.A:
                    return rrset[0].address

        return None
