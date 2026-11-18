"""
Unit tests for app.py HTTP endpoints.
"""

import unittest
import json
from http.server import HTTPServer
import threading
import urllib.request
import urllib.error

from app import SlopSentinelHandler


class TestAppServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), SlopSentinelHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/health"
        req = self.opener.open(url)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertEqual(data.get("status"), "ok")

    def test_classify_valid_text(self):
        url = f"http://127.0.0.1:{self.port}/classify"
        body = json.dumps({"text": "Critical database connection failure"}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        resp = self.opener.open(req)
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode("utf-8"))
        self.assertIn("category", data)
        self.assertIn("urgency", data)
        self.assertIn("confidence", data)
        self.assertIsInstance(data["confidence"], (int, float))

    def test_classify_missing_input(self):
        url = f"http://127.0.0.1:{self.port}/classify"
        body = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.opener.open(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
