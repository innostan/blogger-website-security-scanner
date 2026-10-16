import urllib3
import ipaddress


def make_pinned_pool(hostname, validated_ip, port=443):
    ip = ipaddress.ip_address(validated_ip)

    if not ip.is_global:
        raise ValueError("Blocked: IP address is not public.")

    return urllib3.HTTPSConnectionPool(
        host=validated_ip,
        port=port,
        server_hostname=hostname,
        assert_hostname=hostname,
        cert_reqs="CERT_REQUIRED",
        maxsize=1,
        retries=False,
    )

if __name__ == "__main__":
    hostname = input("Enter domain: ").strip()
    validated_ip = input("Enter validated public IP: ").strip()

    pool = make_pinned_pool(hostname, validated_ip)

    try:
        response = pool.request(
            "GET",
            "/",
            headers={"Host": hostname},
            redirect=False,
            assert_same_host=False,
            preload_content=False,
            timeout=urllib3.Timeout(connect=5, read=5),
        )

        print("HTTP status:", response.status)
        print(
            "Redirect location:",
            response.headers.get("Location", "None"),
        )

        connection = response.connection

        if connection and connection.sock:
            actual_ip = connection.sock.getpeername()[0]
            print("Actual peer IP:", actual_ip)
            print("Matches selected IP:", actual_ip == validated_ip)
        else:
            print("Peer IP unavailable; connection may have closed.")

        response.close()

    except Exception as error:
        print("Connection failed:", error)

    finally:
        pool.close()
