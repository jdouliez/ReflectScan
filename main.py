#!/usr/bin/env python3
"""
Reflected Parameters Scanner
Tool to detect if request parameters are reflected in the HTTP response
"""

import argparse
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Dict, Optional, Tuple
import requests
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import re
import os
import json

# Avoid SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize Colorama
init(autoreset=True)

class RiskLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    CONFIRMED = "Confirm"

@dataclass
class ReflectionResult:
    url: str
    method: str
    parameter: str
    test_value: str
    risk_level: RiskLevel
    response_snippet: str
    status_code: int

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "test_value": self.test_value,
            "risk_level": self.risk_level.value,
            "response_snippet": self.response_snippet,
            "status_code": self.status_code
        }

class ReflectedParamsScanner:
    """Main scanner to detect reflected parameters"""

    def __init__(self, use_colors: bool = True, timeout: int = 10, max_workers: int = 10, json_output: bool = False):
        self.use_colors = use_colors
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'ReflectedParamsScanner/1.0'
        })

        # Test payloads
        self.simple_payload = "ReflectedParamsScanner123"
        self.special_payload = 'ReflectedParamsScanner<>()123'
        self.advanced_payload = 'ReflectedParamsScanner<>()="\'123'

        # Lock for synchronous printing
        self.print_lock = threading.Lock()

        # Track if JSON output is enabled
        self.json_output = json_output

    def colorize(self, text: str, color: str) -> str:
        """Colorize text if colors are enabled"""
        if not self.use_colors:
            return text
        return f"{color}{text}{Style.RESET_ALL}"

    def print_colored(self, message: str, color: str = Fore.WHITE):
        """Print a colorized message in a thread-safe way, only if JSON output is not enabled"""
        if self.json_output:
            return
        with self.print_lock:
            print(self.colorize(message, color))

    def extract_urls_with_params(self, urls: List[str]) -> List[str]:
        """Filter URLs that contain parameters"""
        filtered_urls = []

        for url in urls:
            url = url.strip()
            if not url:
                continue

            try:
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    self.print_colored(f"[SKIP] Invalid URL (missing scheme or netloc): {url}", Fore.YELLOW)
                    continue
                if parsed.query:  # URL contains parameters
                    filtered_urls.append(url)
                else:
                    self.print_colored(f"[SKIP] No parameters: {url}", Fore.YELLOW)
            except Exception as e:
                self.print_colored(f"[SKIP] Invalid URL {url}: {e}", Fore.YELLOW)

        return filtered_urls

    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract parameters from a URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            return dict(urllib.parse.parse_qsl(parsed.query))
        except Exception as e:
            self.print_colored(f"[ERROR] Failed to extract parameters from {url}: {e}", Fore.RED)
            return {}

    def test_reflection(self, url: str, method: str, param_name: str, test_value: str) -> Optional[ReflectionResult]:
        """Test if a parameter is reflected in the response"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                self.print_colored(f"[ERROR] Invalid URL for request: {url}", Fore.RED)
                return None
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

            # Prepare parameters
            original_params = dict(urllib.parse.parse_qsl(parsed_url.query))
            test_params = original_params.copy()
            test_params[param_name] = test_value

            # Make the request according to the method
            if method.upper() == 'GET':
                response = self.session.get(
                    base_url,
                    params=test_params,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                response = self.session.post(
                    base_url,
                    data=test_params,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            # Check if the value is reflected
            response_text = response.text.lower()
            test_value_lower = test_value.lower()

            if test_value_lower in response_text:
                # Find a snippet of the response containing the value
                snippet = self._extract_snippet(response.text, test_value)

                return ReflectionResult(
                    url=url,
                    method=method.upper(),
                    parameter=param_name,
                    test_value=test_value,
                    risk_level=self._assess_risk(test_value),
                    response_snippet=snippet,
                    status_code=response.status_code
                )

        except requests.exceptions.Timeout:
            self.print_colored(f"[TIMEOUT] {method.upper()} {url}", Fore.YELLOW)
        except requests.exceptions.ConnectionError as e:
            self.print_colored(f"[ERROR] Connection error for {method.upper()} {url}: {e}", Fore.RED)
        except requests.exceptions.RequestException as e:
            self.print_colored(f"[ERROR] {method.upper()} {url}: {e}", Fore.RED)
        except Exception as e:
            self.print_colored(f"[ERROR] Unexpected error for {url}: {e}", Fore.RED)

        return None

    def _extract_snippet(self, response_text: str, test_value: str, context_length: int = 100) -> str:
        """Extract a snippet of the response containing the test value"""
        try:
            index = response_text.lower().find(test_value.lower())
            if index != -1:
                start = max(0, index - context_length // 2)
                end = min(len(response_text), index + len(test_value) + context_length // 2)
                snippet = response_text[start:end].strip()

                # Clean the snippet (remove excessive newlines)
                snippet = re.sub(r'\s+', ' ', snippet)
                return snippet[:150] + "..." if len(snippet) > 150 else snippet
        except Exception as e:
            self.print_colored(f"[ERROR] Failed to extract snippet: {e}", Fore.RED)
        return "Snippet not available"

    def _assess_risk(self, test_value: str) -> RiskLevel:
        """Assess the risk level according to the payload used"""
        if test_value == self.simple_payload:
            return RiskLevel.LOW
        elif test_value == self.special_payload:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.CONFIRMED

    def test_single_url(self, url: str) -> List[ReflectionResult]:
        """Test a single URL with all payloads"""
        results = []
        params = self.extract_parameters(url)

        if not params:
            self.print_colored(f"[WARN] No parameters found in {url}", Fore.YELLOW)
            return results

        self.print_colored(f"[INFO] Testing {url} with {len(params)} parameter(s)", Fore.CYAN)

        for param_name in params.keys():
            # Test with different payloads
            payloads = [self.advanced_payload, self.special_payload, self.simple_payload]
            methods = ['GET', 'POST']

            for method in methods:
                for payload in payloads:
                    result = self.test_reflection(url, method, param_name, payload)
                    if result:
                        results.append(result)
                        break

        return results

    def scan_urls(self, urls: List[str]) -> List[ReflectionResult]:
        """Scan a list of URLs with multithreading"""
        # Filter URLs with parameters
        filtered_urls = self.extract_urls_with_params(urls)

        if not filtered_urls:
            self.print_colored("[ERROR] No URL with parameters found", Fore.RED)
            return []

        if len(filtered_urls) < self.max_workers:
            self.max_workers = len(filtered_urls) if len(filtered_urls) > 0 else 1

        self.print_colored(f"[INFO] Scanning {len(filtered_urls)} URLs with {self.max_workers} threads\n", Fore.CYAN)

        all_results = []

        # Use ThreadPoolExecutor for multithreading
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self.test_single_url, url): url for url in filtered_urls}

            # Collect results
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    self.print_colored(f"[ERROR] Error while processing {url}: {e}", Fore.RED)

        return all_results

    def display_results(self, results: List[ReflectionResult]):
        """Display results in a formatted way"""
        if not results:
            self.print_colored("\n[INFO] No parameter reflection detected", Fore.GREEN)
            return

        self.print_colored(f"\n{'='*50}", Fore.WHITE)
        self.print_colored("ANALYSIS RESULTS", Fore.WHITE)
        self.print_colored(f"{'='*50}", Fore.WHITE)

        # Group by risk level
        by_risk = {}
        for result in results:
            risk = result.risk_level.value
            if risk not in by_risk:
                by_risk[risk] = []
            by_risk[risk].append(result)

        # Display by severity order
        risk_colors = {
            RiskLevel.CONFIRMED.value: Fore.RED,
            RiskLevel.MEDIUM.value: Fore.YELLOW,
            RiskLevel.LOW.value: Fore.GREEN
        }

        for risk_level in [RiskLevel.CONFIRMED.value, RiskLevel.MEDIUM.value, RiskLevel.LOW.value]:
            if risk_level in by_risk:
                self.print_colored(f"\n[{risk_level.upper()}] - {len(by_risk[risk_level])} result(s)",
                                 risk_colors.get(risk_level, Fore.WHITE))

                for result in by_risk[risk_level]:
                    self.print_colored(f"  URL: {result.url}", Fore.CYAN)
                    self.print_colored(f"  Method: {result.method}", Fore.BLUE)
                    self.print_colored(f"  Parameter: {result.parameter}", Fore.MAGENTA)
                    self.print_colored(f"  Payload: {result.test_value}", Fore.WHITE)
                    self.print_colored(f"  Status: {result.status_code}", Fore.GREEN if result.status_code == 200 else Fore.YELLOW)
                    self.print_colored(f"  Snippet: {result.response_snippet}", Fore.YELLOW)
                    self.print_colored(f"  {'-'*60}", Fore.WHITE)

    def results_to_json(self, results: List[ReflectionResult]) -> str:
        """Convert results to JSON string"""
        return json.dumps([r.to_dict() for r in results], indent=2)

def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from a file"""
    try:
        if not os.path.isfile(filepath):
            print(f"Error: File '{filepath}' not found")
            sys.exit(1)
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied to read '{filepath}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error while reading the file: {e}")
        sys.exit(1)

def load_urls_from_stdin() -> List[str]:
    """Load URLs from stdin"""
    urls = []
    try:
        for line in sys.stdin:
            url = line.strip()
            if url:
                urls.append(url)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error while reading from stdin: {e}")
        sys.exit(1)
    return urls

def show_help():
    """Display detailed help"""
    help_text = """
Reflected Parameters Scanner v1.0

DESCRIPTION:
    Tool to detect if HTTP request parameters are reflected in the response.
    Useful for identifying potential reflection vulnerabilities (XSS, etc.).

FEATURES:
    - GET and POST support
    - Test with different payloads (simple, special, advanced)
    - Risk level assessment
    - Multithreading for better performance
    - Colorized output
    - JSON output option

RISK LEVELS:
    - Low: Reflection with simple payload
    - Medium: Reflection with special characters
    - Confirmed: Reflection with XSS payload

USAGE:
    # From a file
    python main.py -f urls.txt

    # From stdin
    echo "https://example.com/?param=value" | python main.py
    cat urls.txt | python main.py

    # Single URL
    python main.py -u "https://example.com/?id=123&name=test"

    # Advanced options
    python main.py -f urls.txt -t 20 --threads 20 --no-color

    # JSON output
    python main.py -f urls.txt --json

EXAMPLES:
    python main.py -f targets.txt --threads 15 -t 30
    echo "https://vuln-site.com/?search=test" | python main.py --no-color
    python main.py -f urls.txt --json
    """
    print(help_text)

def main():
    parser = argparse.ArgumentParser(
        description="Scanner to detect reflected parameters in HTTP responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f urls.txt
  echo "https://example.com/?param=value" | python main.py
  python main.py -u "https://site.com/?id=123" --threads 20
  python main.py -f urls.txt --json
        """
    )

    # Group for URL sources
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-f', '--file', help='File containing URLs (one per line)')
    input_group.add_argument('-u', '--url', help='Single URL to test')

    # Configuration options
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-color', action='store_true', help='Disable colorization')
    parser.add_argument('--help-detailed', action='store_true', help='Show detailed help')
    parser.add_argument('--json', action='store_true', help='Output results as JSON (disables text output)')
    
    args = parser.parse_args()
    
    # Show detailed help if requested
    if args.help_detailed:
        show_help()
        sys.exit(0)

    # Determine the source of URLs
    urls = []
    
    if args.url:
        urls = [args.url]
    elif args.file:
        urls = load_urls_from_file(args.file)
    else:
        # Check if stdin has content
        if sys.stdin.isatty():
            print("Error: No URL source specified.")
            print("Use -f for a file, -u for a URL, or pipe via stdin.")
            print("Use --help-detailed for more information.")
            sys.exit(1)
        else:
            urls = load_urls_from_stdin()
    
    if not urls:
        print("Error: No URL to process.")
        sys.exit(1)
    
    # Create and configure the scanner
    scanner = ReflectedParamsScanner(
        use_colors=not args.no_color and not args.json,
        timeout=args.timeout,
        max_workers=args.threads,
        json_output=args.json
    )
    
    # Banner
    if not args.no_color and not args.json:
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.CYAN}REFLECTED PARAMETERS SCANNER v1.0")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    start_time = time.time()

    # Scan the URLs
    results = scanner.scan_urls(urls)
    
    # Display the results
    if args.json:
        print(scanner.results_to_json(results))
    else:
        scanner.display_results(results)
    
    # Final stats
    end_time = time.time()
    duration = end_time - start_time

    if not args.json:
        scanner.print_colored(f"\n[INFO] Scan finished in {duration:.2f}s", Fore.GREEN)
        scanner.print_colored(f"[INFO] {len(results)} reflection(s) detected", Fore.GREEN)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unhandled exception: {e}")
        sys.exit(1)
