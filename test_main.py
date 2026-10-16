
import socket
import unittest
from unittest.mock import patch

from main import validate_url


class TestURLValidation(unittest.TestCase):

    def test_rejects_localhost_ip(self):
        _, error = validate_url("http://127.0.0.1:8000")
        self.assertIsNotNone(error)

    def test_rejects_invalid_scheme(self):
        _, error = validate_url("file:///etc/passwd")
        self.assertIsNotNone(error)

    @patch("main.socket.getaddrinfo")
    def test_rejects_domain_resolving_to_private_ip(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.10", 80))
        ]

        _, error = validate_url("http://example.test")
        self.assertIsNotNone(error)

    @patch("main.socket.getaddrinfo")
    def test_accepts_public_ip_resolution(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("93.184.216.34", 80))
        ]

        parsed, error = validate_url("http://example.test")
        self.assertIsNone(error)
        self.assertIsNotNone(parsed)


    def test_rejects_malformed_port(self):
        _, error = validate_url("http://example.com:abc")
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
