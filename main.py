import ipaddress
import socket
import urllib3
from urllib.parse import urlparse


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def validate_url(url):
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None, "Invalid URL or port."

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, "Enter a valid http:// or https:// URL."

    if parsed.username or parsed.password:
        return None, "URLs containing usernames or passwords are not allowed."

    if port is not None and not 1 <= port <= 65535:
        return None, "Invalid port."

    hostname = parsed.hostname
    port = port or (443 if parsed.scheme == "https" else 80)

    try:
        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            results = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
            
            addresses = sorted(
                {
                   ipaddress.ip_address(item[4][0])
                   for item in results
                },
                key=lambda address: address.version,
            )

        if not addresses:
            return None, "Could not resolve this hostname."

        # Reject the entire hostname if ANY answer is non-public.
        if any(not address.is_global for address in addresses):
            return None, "Blocked: hostname resolves to a non-public IP."

        return (parsed, addresses[0]), None

    except (socket.gaierror, ValueError, OSError):
        return None, "Could not resolve or validate this hostname."


def scan_website():
    print("\nBlogger Website Security Scanner")
    print("-" * 38)
    print("Only scan websites you own or have permission to assess.")

    url = input("Enter the website URL: ").strip()
    result, error = validate_url(url)

    if error:
        print(error)
        return

    parsed, pinned_ip = result
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Preserve the requested hostname in the HTTP Host header.
    host_header = hostname
    if parsed.port is not None:
        host_header = f"{hostname}:{port}"

    # Preserve the URL path and query string.
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    pool = None
    response = None

    try:
        if parsed.scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                host=str(pinned_ip),
                port=port,
                server_hostname=hostname,
                assert_hostname=hostname,
                cert_reqs="CERT_REQUIRED",
                maxsize=1,
                retries=False,
            )
        else:
            pool = urllib3.HTTPConnectionPool(
                host=str(pinned_ip),
                port=port,
                maxsize=1,
                retries=False,
            )

        response = pool.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "BloggerSecurityScanner/0.3",
            },
            redirect=False,
            assert_same_host=False,
            preload_content=False,
            timeout=urllib3.Timeout(connect=5, read=5),
        )

        connection = response.connection
        actual_ip = None

        if connection and connection.sock:
            actual_ip = connection.sock.getpeername()[0]

        if actual_ip is None:
            print("Could not verify the connected peer IP. Scan stopped.")
            return

        if ipaddress.ip_address(actual_ip) != pinned_ip:
            print("Connection IP did not match the validated IP. Scan stopped.")
            return

        print("\nSCAN RESULTS")
        print("-" * 38)
        print(f"Requested URL: {url}")
        print(f"Validated IP: {pinned_ip}")
        print(f"Actual peer IP: {actual_ip}")
        print("Peer IP matches: Yes")
        print(f"HTTP status: {response.status}")
        print(f"HTTPS used: {parsed.scheme == 'https'}")
        print(
            "Content type:",
            response.headers.get("Content-Type", "Not provided"),
        )
        print(
            "Server header:",
            response.headers.get("Server", "Not provided"),
        )

        if response.status in (301, 302, 303, 307, 308):
            print(
                "Redirect detected. It was not followed; "
                "the destination must be validated separately."
            )
            print(
                "Redirect location:",
                response.headers.get("Location", "Not provided"),
            )

        print("\nSECURITY HEADERS")
        for name in SECURITY_HEADERS:
            value = response.headers.get(name)
            if value:
                print(f"[FOUND] {name}: {value}")
            else:
                print(f"[MISSING] {name}")

        print("\nPreliminary check only; this is not a full security audit.")

    except (urllib3.exceptions.HTTPError, OSError, ValueError) as error:
        print(f"Could not complete the scan: {error}")

    finally:
        if response is not None:
            response.close()
        if pool is not None:
            pool.close()


if __name__ == "__main__":
    scan_website()
