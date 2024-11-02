import requests
import time

class AttackEngine:
    def __init__(self, config):
        """
        Initialize the AttackEngine module with configurations for attack parameters.

        :param config: Dictionary containing attack engine configuration options
        """
        self.config = config
        self.timeout = config.get("timeout", 5)
        self.retries = config.get("retries", 2)
        self.payloads = config.get("payloads", {})

    def execute(self, vulnerabilities, target_url):
        """
        Execute attacks on identified vulnerabilities.

        :param vulnerabilities: List of identified vulnerabilities
        :param target_url: The URL of the web application to attack
        :return: Dictionary with results of each attack attempt
        """
        print(f"Executing attacks on {target_url}...")
        results = {}

        # Execute SQL Injection attack if vulnerability detected
        if "SQL Injection" in vulnerabilities:
            results["SQL Injection"] = self.attack_sql_injection(target_url)

        # Execute XSS attack if vulnerability detected
        if "XSS" in vulnerabilities:
            results["XSS"] = self.attack_xss(target_url)

        return results

    def attack_sql_injection(self, target_url):
        """
        Attempt a SQL Injection attack by using payloads to extract basic information.

        :param target_url: The URL of the web application to attack
        :return: Result of the SQL Injection attack
        """
        print("  - Attempting SQL Injection attack...")
        result = {
            "success": False,
            "details": None
        }
        
        for payload in self.payloads.get("sql_injection", []):
            test_url = f"{target_url}?id={payload}"  # Modify parameter based on actual input names

            try:
                response = requests.get(test_url, timeout=self.timeout)
                if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                    print("    -> SQL Injection attack successful with payload:", payload)
                    result["success"] = True
                    result["details"] = f"Successful SQL Injection with payload: {payload}"
                    break
            except requests.RequestException as e:
                print(f"    [Error] Could not execute SQL Injection attack: {e}")
                time.sleep(self.timeout)

        if not result["success"]:
            print("    -> SQL Injection attack failed.")
            result["details"] = "SQL Injection attack failed."

        return result

    def attack_xss(self, target_url):
        """
        Attempt an XSS attack by injecting a script payload to validate reflection.

        :param target_url: The URL of the web application to attack
        :return: Result of the XSS attack
        """
        print("  - Attempting XSS attack...")
        result = {
            "success": False,
            "details": None
        }

        for payload in self.payloads.get("xss", []):
            test_url = f"{target_url}?q={payload}"  # Modify parameter based on actual input names

            try:
                response = requests.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    print("    -> XSS attack successful with payload:", payload)
                    result["success"] = True
                    result["details"] = f"Successful XSS with payload: {payload}"
                    break
            except requests.RequestException as e:
                print(f"    [Error] Could not execute XSS attack: {e}")
                time.sleep(self.timeout)

        if not result["success"]:
            print("    -> XSS attack failed.")
            result["details"] = "XSS attack failed."

        return result

