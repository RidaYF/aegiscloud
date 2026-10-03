from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        print(self.rfile.read(length).decode())
        self.send_response(200)
        self.end_headers()

HTTPServer(('localhost', 8000), Handler).serve_forever()