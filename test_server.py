
from http.server import SimpleHTTPRequestHandler, HTTPServer


class SecurityHeaderHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 3000), SecurityHeaderHandler)
    print("WebShield test server running at http://127.0.0.1:3000")
    print("Header enabled: X-Content-Type-Options: nosniff")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTest server stopped.")
    finally:
        server.server_close()
