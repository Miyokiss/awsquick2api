import os

import uvicorn

from .main import create_app


def main():
    # One process owns OAuth callbacks, refresh locks, and account leases.
    uvicorn.run(create_app(), host=os.getenv("QUICKPOOL_HOST", "127.0.0.1"),
                port=int(os.getenv("QUICKPOOL_PORT", "8045")), workers=1,
                proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()

