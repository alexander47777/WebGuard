from zapv2 import ZAPv2
import time
import requests

class ZapScanner:
    def __init__(self, zap_proxy='http://127.0.0.1:8080', api_key=None):
        """
        Initialize the ZAP Scanner with the ZAP proxy and API key.
        
        :param zap_proxy: The proxy address for ZAP.
        :param api_key: The API key for ZAP (if configured).
        """
        self.zap_proxy = zap_proxy
        self.api_key = api_key
        self.zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy}, apikey=api_key)

    def start_scan(self, target_url):
        """
        Run a spider and active scan on the target URL.
        
        :param target_url: The URL of the target to scan.
        """
        # Step 1: Spider the site
        print(f'Starting OWASP ZAP spider on {target_url}')
        spider_scan_id = self.zap.spider.scan(target_url)
        while int(self.zap.spider.status(spider_scan_id)) < 100:
            print(f'Spider progress: {self.zap.spider.status(spider_scan_id)}%')
            time.sleep(5)
        print('Spidering completed.')

        # Step 2: Active Scan
        print(f'Starting OWASP ZAP active scan on {target_url}')
        active_scan_id = self.zap.ascan.scan(target_url)
        while int(self.zap.ascan.status(active_scan_id)) < 100:
            print(f'Active scan progress: {self.zap.ascan.status(active_scan_id)}%')
            time.sleep(5)
        print('Active scan completed.')

    def get_alerts(self, base_url):
        """
        Fetches alerts from ZAP for the given base URL.
        
        :param base_url: The target URL for which to retrieve alerts.
        :return: List of alerts from ZAP.
        """
        print('Retrieving scan results...')
        alerts = self.zap.core.alerts(baseurl=base_url)

        if not alerts:
            print("No alerts found.")
        return alerts

    def display_alerts(self, alerts):
        """
        Displays the alerts with details including solutions and references.
        
        :param alerts: List of alert dictionaries to display.
        """
        alert_details = []
        if alerts:
            for alert in alerts:
                details = {
                    "Alert": alert['alert'],
                    "Risk": alert['risk'],
                    "URL": alert['url'],
                    "Description": alert['description'],
                    "Solution": alert.get('solution', 'No solution provided'),
                    "References": alert.get('reference', 'No references provided')
                }
                alert_details.append(details)
                print(f"Alert: {details['Alert']}")
                print(f"Risk: {details['Risk']}")
                print(f"URL: {details['URL']}")
                print(f"Description: {details['Description']}")
                print(f"Solution: {details['Solution']}")
                print(f"References: {details['References']}\n")
        else:
            print("No alerts found.")
        
        return alert_details