from http.server import SimpleHTTPRequestHandler, HTTPServer


class SecurityHeaderHandler(SimpleHTTPRequestHandler):
    pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 3000), SecurityHeaderHandler)
    print("WebShield regression test server running at http://127.0.0.1:3000")
    print("Header disabled: X-Content-Type-Options")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTest server stopped.")
    finally:
        server.server_close()
