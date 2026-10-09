import threading
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from assess import assess, validate_target, review
from lab_server import Handler


class AssessmentTests(unittest.TestCase):
    def test_external_targets_rejected(self):
        for url in ('http://example.com', 'http://192.0.2.1', 'file:///etc/passwd', 'http://user:pass@127.0.0.1', 'http://localhost'):
            with self.assertRaises(ValueError):
                validate_target(url)

    def test_loopback(self):
        self.assertEqual(validate_target('http://127.0.0.1:8769/before'), 'http://127.0.0.1:8769/before')

    def test_case_insensitive_headers(self):
        self.assertEqual(review({'Content-Security-Policy': "default-src 'none'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}), [])

    def test_real_http_before_after(self):
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            self.assertEqual(len(assess(base + '/before')['findings']), 3)
            self.assertEqual(assess(base + '/after')['findings'], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_redirect_is_refused(self):
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', 'http://192.0.2.1/')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ValueError):
                assess('http://127.0.0.1:' + str(server.server_port))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
