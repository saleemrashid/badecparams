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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile)

    with http.server.HTTPServer(("0.0.0.0", 443), handler_class) as httpd:
      httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
      httpd.serve_forever()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "certfile",
        help="PEM-encoded file containing private key and full certificate chain.",
    )

    args = parser.parse_args()

    main(args.certfile)
