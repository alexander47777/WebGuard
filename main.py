import sys
import argparse
from core.framework import WebAppPenTestFramework

def main():
    # Set up argument parsing for command-line usage
    parser = argparse.ArgumentParser(description="Web Application Penetration Testing Framework")
    parser.add_argument("url", help="Target URL for the penetration test")
    parser.add_argument("--config", default="config/default_config.yaml", help="Path to the configuration file")
    args = parser.parse_args()

    # Initialize and run the framework with the specified target URL and configuration file
    framework = WebAppPenTestFramework(config_path=args.config)
    framework.run(args.url)

if __name__ == "__main__":
    main()
