import asyncio

from .dns_server import DnsServer


if __name__ == '__main__':
    server = DnsServer()
    asyncio.run(server.start_handling())