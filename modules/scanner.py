import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Scanner:
    def __init__(self, config):
        """
        Initialize the Scanner module with configurations for scanning vulnerabilities.

        :param config: Dictionary containing scanner configuration options
        """
        self.config = config
        self.headers = config.get("custom_headers", {})
        self.visited_urls = set()

    def find_endpoints(self, base_url):
        """
        Crawl the web application to find all potential endpoints for testing.

        :param base_url: The base URL of the web application to crawl
        :return: A list of endpoints and forms found in the web application
        """
        print("Crawling the web application for endpoints...")
        endpoints = []
        try:
            response = requests.get(base_url, headers=self.headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all anchor tags with href attributes
            for link in soup.find_all('a', href=True):
                full_url = urljoin(base_url, link['href'])
                if base_url in full_url and full_url not in self.visited_urls:
                    self.visited_urls.add(full_url)
                    endpoints.append(full_url)

            # Find all forms and extract action URLs and input fields
            for form in soup.find_all('form'):
                form_action = form.get('action')
                form_url = urljoin(base_url, form_action) if form_action else base_url
                inputs = [input_tag.get('name') for input_tag in form.find_all('input') if input_tag.get('name')]
                if form_url not in self.visited_urls:
                    self.visited_urls.add(form_url)
                    endpoints.append({'url': form_url, 'inputs': inputs})
            
            print(f"Endpoints found: {endpoints}")
            return endpoints

        except requests.RequestException as e:
            print(f"    [Error] Failed to crawl {base_url}: {e}")
            return []

    def scan(self, target_url):
        """
        Scan the target URL for vulnerabilities based on configuration settings.

        :param target_url: The URL of the web application to scan
        :return: List of identified vulnerabilities
        """
        endpoints = self.find_endpoints(target_url)
        vulnerabilities = []

        for endpoint in endpoints:
            # Check each endpoint or form for vulnerabilities (SQL Injection, XSS)
            if isinstance(endpoint, dict):  # Endpoint is a form with input fields
                form_url = endpoint['url']
                inputs = endpoint['inputs']
                if self.config.get("sql_injection"):
                    if self.check_sql_injection(form_url, inputs):
                        vulnerabilities.append({"url": form_url, "type": "SQL Injection"})

                if self.config.get("xss"):
                    if self.check_xss(form_url, inputs):
                        vulnerabilities.append({"url": form_url, "type": "XSS"})

            else:  # Endpoint is a simple URL
                if self.config.get("sql_injection"):
                    if self.check_sql_injection(endpoint):
                        vulnerabilities.append({"url": endpoint, "type": "SQL Injection"})

                if self.config.get("xss"):
                    if self.check_xss(endpoint):
                        vulnerabilities.append({"url": endpoint, "type": "XSS"})

        return vulnerabilities

    def check_sql_injection(self, url, inputs=None):
        """
        Check for SQL Injection vulnerability by sending a typical SQL payload.

        :param url: The URL of the web application to test
        :param inputs: List of input field names (for form testing)
        :return: True if SQL Injection vulnerability is detected, else False
        """
        print("  - Checking for SQL Injection...")
        payload = "' OR '1'='1"
        if inputs:
            for input_name in inputs:
                data = {input_name: payload}
                try:
                    response = requests.post(url, data=data, headers=self.headers, timeout=5)
                    if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                        print(f"    -> Potential SQL Injection detected at {url} with input {input_name}")
                        return True
                except requests.RequestException as e:
                    print(f"    [Error] Could not test {url}: {e}")
        else:
            test_url = f"{url}?test_param={payload}"
            try:
                response = requests.get(test_url, headers=self.headers, timeout=5)
                if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                    print(f"    -> Potential SQL Injection detected at {url}")
                    return True
            except requests.RequestException as e:
                print(f"    [Error] Could not test {url}: {e}")

        return False

    def check_xss(self, url, inputs=None):
        """
        Check for XSS vulnerability by injecting a simple script payload.

        :param url: The URL of the web application to test
        :param inputs: List of input field names (for form testing)
        :return: True if XSS vulnerability is detected, else False
        """
        print("  - Checking for XSS...")
        payload = "<script>alert('XSS')</script>"
        if inputs:
            for input_name in inputs:
                data = {input_name: payload}
                try:
                    response = requests.post(url, data=data, headers=self.headers, timeout=5)
                    if payload in response.text:
                        print(f"    -> Potential XSS detected at {url} with input {input_name}")
                        return True
                except requests.RequestException as e:
                    print(f"    [Error] Could not test {url}: {e}")
        else:
            test_url = f"{url}?test_param={payload}"
            try:
                response = requests.get(test_url, headers=self.headers, timeout=5)
                if payload in response.text:
                    print(f"    -> Potential XSS detected at {url}")
                    return True
            except requests.RequestException as e:
                print(f"    [Error] Could not test {url}: {e}")

        return False
