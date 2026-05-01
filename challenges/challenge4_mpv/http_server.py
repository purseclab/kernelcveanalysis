import argparse
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler


class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # 1. Handle the /addr/<integer_param> endpoint
        # Matches base-10 integers or hex (e.g. /addr/12345 or /addr/0xdeadbeef)
        addr_match = re.match(r"^/addr/(\d+|0x[a-fA-F0-9]+)$", self.path)
        if addr_match:
            try:
                # Parse the integer
                addr_val = int(addr_match.group(1), 0)

                # Convert the integer to 8-byte little-endian format
                addr_bytes = addr_val.to_bytes(8, byteorder="little")

                # Construct the payload: /\n\n\n\n\n\n\n + the 8 literal bytes
                payload = b"/\n\n\n\n\n\n\n" + addr_bytes

                # Send the response
                self.send_response(200)
                # CHANGED: Now serves as image/png
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            except OverflowError:
                self.send_error(400, "Integer is too large to fit in 8 bytes")
            except ValueError:
                self.send_error(400, "Invalid integer format")
            return

        # 2. Serve static files under /files/
        if self.path.startswith("/files/"):
            # SimpleHTTPRequestHandler natively translates the URL path to the
            # local filesystem relative to the current working directory.
            # E.g., a request to /files/test.txt looks for ./files/test.txt locally.
            return super().do_GET()

        # 3. Reject anything else
        self.send_error(404, "Not Found")


def main():
    parser = argparse.ArgumentParser(description="Custom Python HTTP Server")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default="0.0.0.0",
        help="Interface to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8000, help="Port to bind to (default: 8000)"
    )

    args = parser.parse_args()

    server_address = (args.interface, args.port)
    httpd = HTTPServer(server_address, CustomHandler)

    print(f"[*] Server listening on {args.interface}:{args.port}")
    print(f"[*] Serving static files from local ./files/ directory at /files/...")
    print(f"[*] Serving binary address payloads at /addr/<integer>")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    main()
