import requests
import tempfile
import http.cookies

class HeaderSecurityCheck:
    def __init__(self):
        """
        Initialize the Header Security Analyzer with an extended list of security headers.
        """
        # Extended list of security headers to check for
        self.security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Feature-Policy",  # Deprecated but still present in some apps
            "Expect-CT",
            "X-XSS-Protection",  # Deprecated but worth checking for legacy systems
            "Public-Key-Pins",  # Deprecated but worth checking for legacy support
            "Cache-Control",
            "Pragma",
            "Access-Control-Allow-Origin",
            "Set-Cookie",  # Will be checked in detail for attributes
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy"
        ]

    def check_headers(self, target_url):
        """
        Analyze the HTTP headers for the target URL and save results to a temp file.

        :param target_url: The target URL to analyze
        :return: Path to the temporary file containing the header analysis results
        """
        results = {}
        try:
            response = requests.get(target_url, timeout=5, allow_redirects=False)
            headers = response.headers

            # Collect Set-Cookie headers from all redirects and the final response
            cookies = []
            for r in response.history + [response]:
                if 'Set-Cookie' in r.headers:
                    cookies.extend(r.headers.getlist('Set-Cookie') if hasattr(r.headers, 'getlist') else [r.headers['Set-Cookie']])
            
            # Print response headers for debugging
            print("Response Headers:", headers)

            for header in self.security_headers:
                if header == "Set-Cookie" and cookies:
                    # Special handling for 'Set-Cookie' header to check for 'Secure' and 'HttpOnly' attributes
                    cookie_analysis = []
                    for cookie in cookies:
                        parsed_cookie = http.cookies.SimpleCookie(cookie)
                        for key, morsel in parsed_cookie.items():
                            secure_flag = "secure" in morsel.output().lower()
                            httponly_flag = "httponly" in morsel.output().lower()
                            analysis = (
                                f"Cookie Name: {key}, "
                                f"Secure: {'Present' if secure_flag else 'Not present'}, "
                                f"HttpOnly: {'Present' if httponly_flag else 'Not present'}"
                            )
                            cookie_analysis.append(analysis)
                    results[header] = cookie_analysis
                elif header in headers:
                    # Specific analysis for X-XSS-Protection and Public-Key-Pins
                    if header == "X-XSS-Protection":
                        results[header] = f"{headers[header]} - Recommended: '1; mode=block' for protection"
                    elif header == "Public-Key-Pins":
                        results[header] = f"{headers[header]} - Note: Deprecated but should have been configured with caution"
                    else:
                        results[header] = headers[header]
                else:
                    results[header] = "Not present"

            # Write results to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as temp_file:
                for header, value in results.items():
                    if isinstance(value, list):
                        temp_file.write(f"{header}:\n")
                        for analysis in value:
                            temp_file.write(f"  {analysis}\n")
                    else:
                        temp_file.write(f"{header}: {value}\n")
                
                temp_file_path = temp_file.name

            return temp_file_path

        except requests.RequestException as e:
            print(f"[Error] Failed to fetch headers from {target_url}: {e}")
            results = {"Error": f"Failed to fetch headers: {e}"}

            # Write error to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as temp_file:
                temp_file.write(f"[Error] Failed to fetch headers: {e}\n")
                temp_file_path = temp_file.name

            return temp_file_path
