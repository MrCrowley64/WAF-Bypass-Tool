#!/usr/bin/env python3

import json
import os
import random
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse


class WAFBypass:
    def __init__(self, host, proxy, headers, block_code, timeout, threads, wb_result, wb_result_json, details, no_progress, replay, exclude_dir):
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy} if proxy else {}
        self.headers = headers
        self.block_code = block_code
        self.timeout = timeout
        self.threads = threads
        self.wb_result = wb_result
        self.wb_result_json = wb_result_json
        self.details = details
        self.no_progress = no_progress
        self.replay = replay
        self.exclude_dir = exclude_dir

        self.payloads_dir = Path(__file__).parent.parent / 'payloads'
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.results = {
            'passed': [],
            'blocked': [],
            'failed': [],
            'false_positive': [],
            'false_negative': []
        }

        self.total_tests = 0
        self.completed_tests = 0

    def load_payloads(self):
        """Load all payloads from the payloads directory"""
        payloads = {}

        if not self.payloads_dir.exists():
            print(f"Warning: Payloads directory not found at {self.payloads_dir}")
            return payloads

        for category_dir in self.payloads_dir.iterdir():
            if not category_dir.is_dir():
                continue

            category_name = category_dir.name.upper()

            # Skip excluded directories
            if category_name in self.exclude_dir:
                continue

            payloads[category_name] = []

            for payload_file in category_dir.glob('*.txt'):
                try:
                    with open(payload_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                payloads[category_name].append({
                                    'payload': line,
                                    'file': str(payload_file.name),
                                    'category': category_name
                                })
                except Exception as e:
                    print(f"Error reading {payload_file}: {e}")

        return payloads

    def test_payload(self, payload_data):
        """Test a single payload against the target"""
        payload = payload_data['payload']
        category = payload_data['category']
        file_name = payload_data['file']

        try:
            # Test with different injection points
            test_cases = [
                {'method': 'GET', 'params': {'test': payload}},
                {'method': 'POST', 'data': {'test': payload}},
                {'method': 'GET', 'headers': {'X-Test': payload}},
            ]

            for test_case in test_cases:
                method = test_case['method']

                request_kwargs = {
                    'timeout': self.timeout,
                    'verify': False,
                    'allow_redirects': True
                }

                if self.proxy:
                    request_kwargs['proxies'] = self.proxy

                if 'params' in test_case:
                    request_kwargs['params'] = test_case['params']
                elif 'data' in test_case:
                    request_kwargs['data'] = test_case['data']

                if 'headers' in test_case:
                    request_kwargs['headers'] = {**self.headers, **test_case['headers']}

                response = self.session.request(method, self.host, **request_kwargs)

                result = {
                    'category': category,
                    'file': file_name,
                    'payload': payload,
                    'method': method,
                    'status_code': response.status_code,
                    'blocked': response.status_code in self.block_code,
                    'curl': self._generate_curl(method, test_case, payload) if self.replay else None
                }

                self.completed_tests += 1

                if not self.no_progress and not self.wb_result_json:
                    progress = (self.completed_tests / self.total_tests) * 100
                    print(f"\rProgress: {progress:.1f}% ({self.completed_tests}/{self.total_tests})", end='', flush=True)

                return result

        except requests.exceptions.Timeout:
            return {
                'category': category,
                'file': file_name,
                'payload': payload,
                'method': 'UNKNOWN',
                'status_code': 0,
                'blocked': False,
                'error': 'Timeout',
                'curl': None
            }
        except Exception as e:
            return {
                'category': category,
                'file': file_name,
                'payload': payload,
                'method': 'UNKNOWN',
                'status_code': 0,
                'blocked': False,
                'error': str(e),
                'curl': None
            }

    def _generate_curl(self, method, test_case, payload):
        """Generate cURL command for replay"""
        curl_cmd = f"curl -X {method} '{self.host}'"

        if 'params' in test_case:
            curl_cmd += f"?test={payload}"
        elif 'data' in test_case:
            curl_cmd += f" -d 'test={payload}'"

        for header, value in self.headers.items():
            curl_cmd += f" -H '{header}: {value}'"

        if 'headers' in test_case:
            for header, value in test_case['headers'].items():
                curl_cmd += f" -H '{header}: {value}'"

        return curl_cmd

    def analyze_results(self):
        """Analyze test results and categorize them"""
        total_passed = 0
        total_blocked = 0
        total_failed = 0

        for result in self.results['passed']:
            if not result.get('blocked', False):
                total_passed += 1
            else:
                total_blocked += 1

        for result in self.results['failed']:
            total_failed += 1

        # Calculate bypass rate
        total = total_passed + total_blocked + total_failed
        bypass_rate = (total_passed / total * 100) if total > 0 else 0

        return {
            'total': total,
            'passed': total_passed,
            'blocked': total_blocked,
            'failed': total_failed,
            'bypass_rate': bypass_rate
        }

    def print_results(self):
        """Print test results"""
        analysis = self.analyze_results()

        if self.wb_result_json:
            output = {
                **self.wb_result,
                'RESULTS': {
                    'total_tests': analysis['total'],
                    'bypassed': analysis['passed'],
                    'blocked': analysis['blocked'],
                    'failed': analysis['failed'],
                    'bypass_rate': f"{analysis['bypass_rate']:.2f}%"
                }
            }

            if self.details:
                output['DETAILS'] = {
                    'passed': self.results['passed'],
                    'blocked': self.results['blocked'],
                    'failed': self.results['failed']
                }

            print(json.dumps(output, indent=2))
        else:
            print("\n")
            print("=" * 60)
            print("RESULTS")
            print("=" * 60)
            print(f"Total Tests:    {analysis['total']}")
            print(f"Bypassed (✓):   {analysis['passed']}")
            print(f"Blocked (✗):    {analysis['blocked']}")
            print(f"Failed:         {analysis['failed']}")
            print(f"Bypass Rate:    {analysis['bypass_rate']:.2f}%")
            print("=" * 60)

            if self.details and analysis['passed'] > 0:
                print("\nBYPASSED PAYLOADS:")
                print("-" * 60)
                for result in self.results['passed']:
                    if not result.get('blocked', False):
                        print(f"[{result['category']}] {result['payload'][:80]}")
                        if self.replay and result.get('curl'):
                            print(f"  cURL: {result['curl']}")

            if self.details and analysis['blocked'] > 0:
                print("\nBLOCKED PAYLOADS:")
                print("-" * 60)
                for result in self.results['blocked']:
                    print(f"[{result['category']}] {result['payload'][:80]}")
                    if self.replay and result.get('curl'):
                        print(f"  cURL: {result['curl']}")

    def start(self):
        """Start the WAF bypass testing"""
        if not self.wb_result_json:
            print("Loading payloads...")

        payloads = self.load_payloads()

        if not payloads:
            print("No payloads found. Please add payload files to the payloads directory.")
            return

        # Flatten payloads into a list
        all_payloads = []
        for category, payload_list in payloads.items():
            all_payloads.extend(payload_list)

        self.total_tests = len(all_payloads)

        if not self.wb_result_json:
            print(f"Loaded {self.total_tests} payloads from {len(payloads)} categories")
            print(f"Categories: {', '.join(payloads.keys())}")
            print("\nStarting tests...\n")

        # Test baseline connectivity
        try:
            baseline = self.session.get(self.host, timeout=self.timeout, verify=False, proxies=self.proxy)
            if not self.wb_result_json:
                print(f"Baseline request: {baseline.status_code}")
        except Exception as e:
            print(f"Error connecting to target: {e}")
            return

        # Run tests in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload): payload for payload in all_payloads}

            for future in as_completed(futures):
                try:
                    result = future.result()

                    if result.get('error'):
                        self.results['failed'].append(result)
                    elif result.get('blocked'):
                        self.results['blocked'].append(result)
                    else:
                        self.results['passed'].append(result)

                except Exception as e:
                    if not self.wb_result_json:
                        print(f"\nError processing result: {e}")

        if not self.no_progress and not self.wb_result_json:
            print("\n")

        self.print_results()
