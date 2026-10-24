import asyncio
import logging

from .dns_server import DnsServer


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    server = DnsServer()
    asyncio.run(server.start_handling())
