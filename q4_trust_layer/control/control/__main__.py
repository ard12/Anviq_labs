"""Run the control plane:  python -m control --port 9300 [--policy my_policy.json]"""

from __future__ import annotations

import argparse
import logging
import sys

from control.http_api import make_server
from control.policy import PolicyError, PolicyTable
from control.service import ControlService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="control", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9300)
    parser.add_argument("--policy", help="policy JSON file (default: the table shipped in the package)")
    parser.add_argument("--verbose", action="store_true", help="also log every HTTP request")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        policy = PolicyTable.from_file(args.policy) if args.policy else PolicyTable.default()
    except (PolicyError, OSError) as exc:
        print(f"control: {exc}", file=sys.stderr)
        return 2

    server = make_server(ControlService(policy), args.host, args.port)
    logging.getLogger("control").info("control plane listening on http://%s:%d", args.host, server.server_address[1])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
