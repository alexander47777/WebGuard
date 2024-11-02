from datetime import datetime
import pdfkit
import os

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        """
        Initialize the ReportGenerator with an output directory for reports.
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, target_url, whatweb_result, vulnerabilities, attack_results, ssl_results=None, header_results=None, zap_alerts=None):
        """
        Generate a PDF report of the findings.

        :param target_url: The target URL of the web application
        :param whatweb_result: The output of the WhatWeb scan
        :param vulnerabilities: List of vulnerabilities found
        :param attack_results: Dictionary of attack results
        :param ssl_results: SSL/TLS check results (optional)
        :param header_results: HTTP header analysis results (optional)
        :return: Path to the generated report
        """
        html_content = self._generate_html(target_url, whatweb_result, vulnerabilities, attack_results, ssl_results, header_results, zap_alerts)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = os.path.join(self.output_dir, f"report_{timestamp}.pdf")
        
        pdfkit.from_string(html_content, report_filename)
        print(f"Report generated: {report_filename}")
        return report_filename

    def _generate_html(self, target_url, whatweb_result, vulnerabilities, attack_results, ssl_results=None, header_results=None, zap_alerts=None):
        """
        Generate the HTML content for the report.
        """
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_whatweb_result = whatweb_result.replace(", ", ",\n") if whatweb_result else "No WhatWeb results"

        # Format SSL/TLS check results if provided
        ssl_results_html = ""
        if ssl_results:
            ssl_results_html = f"""
            <div class="section">
                <h3>SSL/TLS Check Results</h3>
                <pre>{ssl_results}</pre>
            </div>
            """

        # Format header analysis results if provided
        header_results_html = ""
        if header_results:
            header_results_html = f"""
            <div class="section">
                <h3>HTTP Header Security Analysis</h3>
                <pre>{header_results}</pre>
            </div>
            """

        # Include ZAP alerts in the report
        zap_alerts_html = ""
        if zap_alerts:
            for alert in zap_alerts:
                zap_alerts_html += f"""
                <div>
                    <h3>Alert: {alert['alert']}</h3>
                    <p><strong>Risk:</strong> {alert['risk']}</p>
                    <p><strong>URL:</strong> {alert['url']}</p>
                    <p><strong>Description:</strong> {alert['description']}</p>
                    <p><strong>Solution:</strong> {alert.get('solution', 'No solution provided')}</p>
                    <p><strong>References:</strong> {alert.get('reference', 'No references provided')}</p>
                </div>
                <hr>
                """

        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Penetration Testing Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                h1, h3 {{ color: #333; }}
                pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; white-space: pre-wrap; }}
                ul {{ margin: 0; padding: 0; }}
                li {{ list-style: none; padding: 5px 0; }}
                .section {{ margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>Penetration Testing Report</h1>
            <p><strong>Target URL:</strong> {target_url}</p>
            <p><strong>Generated on:</strong> {date}</p>

            <div class="section">
                <h3>WhatWeb Scan Results</h3>
                <pre>{formatted_whatweb_result}</pre>
            </div>

            {ssl_results_html}
            {header_results_html}
            {zap_alerts_html}

            <div class="section">
                <h3>Identified Vulnerabilities</h3>
                <ul>{''.join(f'<li>{v}</li>' for v in vulnerabilities)}</ul>
            </div>

            <div class="section">
                <h3>Attack Results</h3>
                <ul>{''.join(f'<li>{v}: {"Success" if r["success"] else "Failure"} - {r["details"]}</li>' for v, r in attack_results.items())}</ul>
            </div>
        </body>
        </html>
        """
        return html_template
