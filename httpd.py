#!/usr/bin/env python3
import functools
import http.server
import os
import ssl
import sys

WWW_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "www")


def main(certfile: str) -> None:
    handler_class = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=WWW_DIRECTORY
    )
    server = http.server.HTTPServer(("0.0.0.0", 443), handler_class)
    server.socket = ssl.wrap_socket(
        server.socket,
        server_side=True,
        certfile=certfile,
        ssl_version=ssl.PROTOCOL_TLSv1_2,
    )
    server.serve_forever()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "certfile",
        help="PEM-encoded file containing private key and full certificate chain.",
    )

    args = parser.parse_args()

    main(args.certfile)
