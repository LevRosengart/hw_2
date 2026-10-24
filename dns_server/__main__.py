import asyncio
import logging

from .dns_server import DnsServer


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    server = DnsServer("199.7.83.42", 5553)
    asyncio.run(server.start_handling())
