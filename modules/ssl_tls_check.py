import ssl
import socket
import tempfile

class SSLTLSCheck:
    def __init__(self, config=None):
        self.config = config

    def check_ssl_tls(self, target_url):
        """
        Perform an SSL/TLS check and write results to a temporary file.
        """
        ssl_info = {
            "valid_certificate": False,
            "certificate_expiration": None,
            "secure_protocol": None,
            "error": None
        }

        try:
            # Extract hostname from URL
            hostname = target_url.split("//")[-1].split("/")[0]
            context = ssl.create_default_context()

            # Connect to the server
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["valid_certificate"] = True
                    ssl_info["certificate_expiration"] = cert.get("notAfter")
                    ssl_info["secure_protocol"] = ssock.version()
        except Exception as e:
            ssl_info["error"] = str(e)

        # Write results to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".txt") as temp_file:
            temp_file.write(f"Valid Certificate: {ssl_info['valid_certificate']}\n")
            temp_file.write(f"Certificate Expiration: {ssl_info['certificate_expiration']}\n")
            temp_file.write(f"Secure Protocol: {ssl_info['secure_protocol']}\n")
            temp_file.write(f"Error: {ssl_info['error'] if ssl_info['error'] else 'None'}\n")
            return temp_file.name  # Return the name of the temporary file
