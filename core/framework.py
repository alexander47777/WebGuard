import re
import yaml
import subprocess
import os
import tempfile
from modules.scanner import Scanner
from modules.attack_engine import AttackEngine
from modules.reporting import ReportGenerator
from modules.ssl_tls_check import SSLTLSCheck
from modules.header_security import HeaderSecurityCheck
from modules.zap_scanner import ZapScanner
from modules.sqlmap_scanner import SQLMapScanner


class WebAppPenTestFramework:
    def __init__(self, config_path="config/default_config.yaml", target_url=None):
        """
        Initialize the WebAppPenTestFramework with configurations.
        Run WhatWeb scan before initializing other modules.

        :param config_path: Path to the YAML configuration file
        :param target_url: The target URL to run WhatWeb scan on
        """


        # Load configuration
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        

        # Run WhatWeb scan before initializing other components
        self.whatweb_result = None
        if target_url:
            self.whatweb_result = self.run_whatweb_scan(target_url)

        # Initialize modules with their respective configuration sections
        self.sqlmap_scanner = SQLMapScanner()
        zap_api_key = self.config.get("zap", {}).get("api_key", None)
        self.zap_scanner = ZapScanner(zap_proxy="http://localhost:8080", api_key=zap_api_key)
        self.ssl_tls_checker = SSLTLSCheck(self.config.get("ssl_tls", {}))
        self.header_security_checker = HeaderSecurityCheck()
        self.scanner = Scanner(self.config.get("scanner", {}))
        self.attack_engine = AttackEngine(self.config.get("attack_engine", {}))
        self.report_generator = ReportGenerator(self.config.get("reporting", {}).get("report_path", "reports"))

    def run_whatweb_scan(self, target_url):
        """
        Run WhatWeb scan on the target URL to gather initial site information and format the output.

        :param target_url: The URL of the web application to scan with WhatWeb
        :return: Formatted WhatWeb scan result as a string
        """
        print(f"Running WhatWeb scan on {target_url}...")
        try:
            # Run WhatWeb using subprocess and capture the output
            result = subprocess.run(['/usr/bin/whatweb', target_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                # Clean up the output by removing escape sequences and formatting with line breaks
                cleaned_output = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', result.stdout)
                formatted_output = cleaned_output.replace(', ', ',\n')
                print(f"WhatWeb scan completed:\n{formatted_output}")
                with open("whatweb_scan_result.txt", "w") as file:
                    file.write(formatted_output)
                return formatted_output
            else:
                print(f"[Error] WhatWeb scan failed: {result.stderr}")
                return "[Error] WhatWeb scan failed"
        except FileNotFoundError:
            print("[Error] WhatWeb is not installed or not found in PATH.")
            return "[Error] WhatWeb is not installed or not found in PATH."

    def run_sql_injection_scan(self, target_url):
        print("Running SQLMap scan for SQL injection...")
        sqlmap_results = self.sqlmap_scanner.run_scan(target_url)
        print("SQLMap scan completed.")
        return sqlmap_results

    def run(self, target_url):
        """
        Run the penetration testing framework on the specified target URL.

        :param target_url: The URL of the web application to test
        """
        
        print(f"Starting penetration test for {target_url}...\n")


        # Run ZAP scan
        print("Running ZAP scan...")
        self.zap_scanner.start_scan(target_url)
        zap_alerts = self.zap_scanner.get_alerts(target_url)
        print(f"ZAP scan completed. Alerts found: {len(zap_alerts)}\n")

        
        # Step: Run SSL/TLS check
        print("Running SSL/TLS checks.......")
        ssl_tls_temp_file = self.ssl_tls_checker.check_ssl_tls(target_url)
        # Read the contents of the temporary file instead of passing the file path
        with open(ssl_tls_temp_file, 'r') as file:
            ssl_results = file.read()

        print(f"SSL/TLS check completed. Results written to: {ssl_tls_temp_file}\n")

        print("Running Sqlmap.......")
        sqlmap_results = self.run_sql_injection_scan(target_url)
        with open("sqlmap_scan_results.txt", "w") as file:
            file.write(sqlmap_results)


        # Step: Run Header Security Analysis
        print("Running HTTP Header Security Analysis...")
        header_results_temp_file = self.header_security_checker.check_headers(target_url)
        with open(header_results_temp_file, 'r') as file:
            header_results = file.read()
        print(f"HTTP Header Security Analysis completed:\n{header_results}\n")

        # Make sure WhatWeb runs at the start of the run process
        if not self.whatweb_result:
            self.whatweb_result = self.run_whatweb_scan(target_url)

        # Step 1: Scan for vulnerabilities
        print("Step 1: Scanning for vulnerabilities...")
        vulnerabilities = self.scanner.scan(target_url)
        print(f"Vulnerabilities found: {vulnerabilities}\n")

        # Step 2: Execute attacks on discovered vulnerabilities
        print("Step 2: Executing attacks on discovered vulnerabilities...")
        attack_results = self.attack_engine.execute(vulnerabilities, target_url)
        print(f"Attack results: {attack_results}\n")

        # Step 3: Generate a report based on the scan, attack results, and WhatWeb output
        print("Step 3: Generating PDF report...")
        report_path = self.report_generator.generate_report(
            target_url, 
            self.whatweb_result, 
            vulnerabilities, 
            attack_results, 
            ssl_results, 
            header_results,
            zap_alerts
        )

        print(f"Report saved to: {report_path}")
