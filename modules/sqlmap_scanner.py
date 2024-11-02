import subprocess

class SQLMapScanner:
    def __init__(self, sqlmap_path='sqlmap'):
        """
        Initialize the SQLMapScanner.
        
        :param sqlmap_path: Path to the sqlmap executable.
        """
        self.sqlmap_path = sqlmap_path

    def run_scan(self, target_url, params=None):
        """
        Run sqlmap to detect SQL injection vulnerabilities.
        
        :param target_url: The URL to test for SQL injection.
        :param params: Optional URL parameters to test.
        :return: Results of the sqlmap scan as a string.
        """
        try:
            command = [self.sqlmap_path, '-u', target_url, '--batch','--level 2', '--risk 2', '--threads 10' , '--output-dir=./sqlmap_output']
            if params:
                command.extend(['--data', params])
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                print(f"SQLMap scan completed on {target_url}")
                return result.stdout
            else:
                print(f"SQLMap encountered an error: {result.stderr}")
                return f"Error: {result.stderr}"

        except FileNotFoundError:
            print("[Error] sqlmap is not installed or not found in PATH.")
            return "[Error] sqlmap is not installed or not found in PATH."
