#!/usr/bin/env python3
"""
API Security Assessment Script
This script performs comprehensive security testing on APIs using Postman collections
and generates a detailed vulnerability report based on OWASP API Security Top 10.
"""

import json
import os
import time
import sys
import subprocess
import argparse
import requests
import logging
from datetime import datetime
from zapv2 import ZAPv2
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Template
import ssl
import socket
import re
import base64
from collections import Counter

# Suppress InsecureRequestWarning for requests made with verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define constants
REPORT_DIR = "security_report"

# Common ZAP installation paths
COMMON_ZAP_PATHS = [
    "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",  # macOS
    "/usr/share/zaproxy/zap.sh",  # Linux
    "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat",  # Windows
    "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\zap.bat"  # Windows 32-bit
]
OWASP_API_TOP_10 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs"
}

class APISecurityAssessment:
    def __init__(self, postman_collection, zap_host='localhost', zap_port=8080, api_key=None, zap_path=None, skip_zap=False):
        """Initialize with Postman collection and optional API key"""
        self.collection = self._load_collection(postman_collection)
        self.api_key = api_key
        self.zap_path = zap_path
        self.skip_zap = skip_zap
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_key = api_key
        self.zap = None
        self.vulnerabilities = []
        self.api_endpoints = []
        self.scan_results = {}
        self.active_scan_id = None
        # Create report directory
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
    
    def _load_collection(self, collection_data):
        """Load Postman collection from JSON data"""
        logger.info("Loading Postman collection...")
        
        if isinstance(collection_data, str):
            try:
                return json.loads(collection_data)
            except json.JSONDecodeError:
                try:
                    with open(collection_data, 'r') as f:
                        return json.load(f)
                except:
                    logger.error("Failed to load collection from file or string")
                    sys.exit(1)
        else:
            return collection_data
    
    def start_zap(self):
        """Start OWASP ZAP and connect to it"""
        logger.info("Starting OWASP ZAP...")
        
        # Skip ZAP if requested
        if self.skip_zap:
            logger.info("Skipping ZAP as requested with --skip-zap flag")
            return
        
        try:
            # Configure connection with retry settings
            session = requests.Session()
            session.verify = False
            retry_strategy = urllib3.Retry(
                total=5,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )
            adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Attempt to connect using provided details with timeout
            zap_proxy = {"http": f"http://{self.zap_host}:{self.zap_port}", "https": f"http://{self.zap_host}:{self.zap_port}"}
            self.zap = ZAPv2(apikey=self.zap_key, proxies=zap_proxy)
            
            # Test connection with timeout
            try:
                self.zap.core.version
                logger.info(f"Connected to existing ZAP instance at {self.zap_host}:{self.zap_port}")
                return
            except requests.exceptions.Timeout:
                logger.error("Connection to ZAP timed out")
                raise
            except requests.exceptions.ConnectionError:
                logger.error("Failed to connect to ZAP proxy")
                raise
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not connect to existing ZAP instance: {e}. Attempting to start ZAP...")
        except Exception as e:
            logger.warning(f"An unexpected error occurred while connecting to ZAP: {e}")

        # If we reach here, connection failed.
        self.zap = None # Ensure zap is None if connection failed

        # If skip_zap is true, don't try to start ZAP
        if self.skip_zap:
            logger.warning("OWASP ZAP is not available. Continuing with limited functionality.")
            logger.warning("Some security tests that require ZAP will be skipped.")
            return # Explicitly return
            
        zap_path = self._find_zap_executable()
        if not zap_path:
            logger.error("Failed to find ZAP executable. Please install OWASP ZAP or specify its location.")
            logger.error("Installation instructions: https://www.zaproxy.org/download/")
            # ... (removed redundant error messages already printed by _find_zap_executable)
            logger.warning("OWASP ZAP is not available. Continuing with limited functionality.")
            logger.warning("Some security tests that require ZAP will be skipped.")
            return # Explicitly return
            
        try:
            # Start ZAP with the found executable
            zap_command = [
                zap_path,
                '-daemon',
                '-host', self.zap_host,
                '-port', str(self.zap_port),
                '-config', f'api.key={self.zap_key if self.zap_key else ""}',
                '-config', 'api.disablekey=false'
            ]
            logger.info(f"Executing ZAP start command: {' '.join(zap_command)}")
            subprocess.Popen(zap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait for ZAP to start with polling
            logger.info("Waiting for ZAP to start...")
            max_attempts = 10
            for attempt in range(max_attempts):
                try:
                    time.sleep(3)  # Wait between attempts
                    self.zap = ZAPv2(apikey=self.zap_key, proxies=zap_proxy)
                    self.zap.core.version  # Check connection
                    logger.info(f"ZAP started successfully after {attempt + 1} attempts at {self.zap_host}:{self.zap_port}")
                    return
                except Exception:
                    logger.info(f"Waiting for ZAP to start (attempt {attempt + 1}/{max_attempts})")
            
            # If we get here, ZAP didn't start properly
            logger.error("Failed to connect to ZAP after multiple attempts")
            self.zap = None # Ensure zap is None
            logger.warning("OWASP ZAP could not be started or connected to. Continuing with limited functionality.")
            logger.warning("Some security tests that require ZAP will be skipped.")
            return # Explicitly return

        except Exception as e:
            logger.error(f"Failed to start or connect to ZAP: {e}")
            self.zap = None # Ensure zap is None
            logger.warning("OWASP ZAP could not be started due to an error. Continuing with limited functionality.")
            logger.warning("Some security tests that require ZAP will be skipped.")
            return # Explicitly return

    def _find_zap_executable(self):
        """Find the ZAP executable in common installation locations"""
        # First check if user provided a custom path
        if self.zap_path:
            if os.path.isfile(self.zap_path):
                logger.info(f"Using user-provided ZAP path: {self.zap_path}")
                return self.zap_path
            else:
                logger.warning(f"User-provided ZAP path not found: {self.zap_path}")
        
        # Next check if zap.sh is in PATH
        try:
            zap_path = subprocess.check_output(['which', 'zap.sh'], stderr=subprocess.DEVNULL).decode().strip()
            if zap_path:
                logger.info(f"Found ZAP in PATH: {zap_path}")
                return zap_path
        except subprocess.CalledProcessError:
            pass  # Not in PATH, continue checking common locations
        
        # Check common installation paths
        for path in COMMON_ZAP_PATHS:
            if os.path.isfile(path):
                logger.info(f"Found ZAP at: {path}")
                return path
        
        # Not found in common locations
        return None

    def extract_endpoints(self):
        """Extract API endpoints from the Postman collection"""
        logger.info("Extracting API endpoints from collection...")

        def process_item(item):
            if 'item' in item:
                # This is a folder containing more items
                for sub_item in item['item']:
                    process_item(sub_item)
            else:
                # This is an actual endpoint
                request = item.get('request', {})
                url_info = request.get('url', {})
                
                # Construct the full URL
                if isinstance(url_info, dict):
                    base_url = "https://api.example.com"  # Default base URL for testing
                    path = '/'.join(url_info.get('path', []))
                    url = f"{base_url}/{path}"
                else:
                    url = url_info

                endpoint = {
                    'name': item.get('name'),
                    'method': request.get('method'),
                    'url': url,
                    'headers': request.get('header', []),
                    'body': request.get('body', {}).get('raw', '{}')
                }
                self.api_endpoints.append(endpoint)
                logger.info(f"Extracted endpoint: {endpoint['name']} - {endpoint['method']} {endpoint['url']}")

        # Process all items in the collection
        for item in self.collection.get('item', []):
            process_item(item)
    
    def import_to_zap(self):
        """Import API endpoints to ZAP"""
        logger.info("Importing API endpoints to ZAP...")
        
        # Skip if ZAP is not available or if skip_zap is enabled
        if self.zap is None or self.skip_zap:
            logger.warning("ZAP is not available or skipped. Skipping import to ZAP.")
            return
        
        for endpoint in self.api_endpoints:
            url = endpoint['url']
            
            # Create OpenAPI spec for this endpoint
            openapi_spec = {
                "openapi": "3.0.0",
                "info": {"title": endpoint['name'], "version": "1.0.0"},
                "paths": {
                    "/" + "/".join(url.split("/")[3:]): {
                        endpoint['method'].lower(): {
                            "summary": endpoint['name'],
                            "parameters": [
                                {"name": h['key'], "in": "header", "required": True} 
                                for h in endpoint['headers']
                            ],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "object"}
                                    }
                                }
                            },
                            "responses": {"200": {"description": "OK"}}
                        }
                    }
                },
                "servers": [{"url": "/".join(url.split("/")[:3])}]
            }
            
            spec_file = f"{REPORT_DIR}/{endpoint['name'].replace(' ', '_')}_openapi.json"
            with open(spec_file, 'w') as f:
                json.dump(openapi_spec, f)
            
            # Import OpenAPI spec to ZAP with retries
            max_retries = 3
            retry_delay = 2
            for attempt in range(max_retries):
                try:
                    self.zap.openapi.import_file(spec_file)
                    logger.info(f"Imported {endpoint['name']} to ZAP")
                    break
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1}/{max_retries} failed to import {endpoint['name']}. Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        logger.error(f"Failed to import {endpoint['name']} after {max_retries} attempts: {e}")
                        raise
    
    def configure_authentication(self):
        """Configure API authentication in ZAP"""
        logger.info("Configuring authentication...")
        
        # Skip if ZAP is not available or if skip_zap is enabled
        if self.zap is None or self.skip_zap:
            logger.warning("ZAP is not available or skipped. Skipping authentication configuration.")
            return
            
        if not self.api_key:
            logger.warning("No API key provided. Skipping authentication configuration.")
            return
        
        # Set up authentication script
        script_name = "API_Auth"
        auth_script = """
        function processHttpMessage(msg) {
            msg.getRequestHeader().setHeader('x-api-key', '%s');
            return msg;
        }
        """ % self.api_key
        
        script_file = f"{REPORT_DIR}/auth_script.js"
        with open(script_file, 'w') as f:
            f.write(auth_script)
        
        # Load the script to ZAP
        self.zap.script.load(
            scriptname=script_name,
            scripttype='httpsender',
            scriptengine='Oracle Nashorn',
            filename=script_file,
            scriptdescription='API Authentication'
        )
        
        self.zap.script.enable(scriptname=script_name)
        logger.info("Authentication script configured")
    
    def run_passive_scan(self):
        """Run passive scanning"""
        logger.info("Running passive scan...")
        
        # Skip if ZAP is not available or if skip_zap is enabled
        if self.zap is None or self.skip_zap:
            logger.warning("ZAP is not available or skipped. Skipping passive scan.")
            return
        
        # Ensure passive scanner is enabled
        self.zap.pscan.enable_all_scanners()
        
        # Spider the target to discover content
        for endpoint in self.api_endpoints:
            base_url = "/".join(endpoint['url'].split("/")[:3])
            logger.info(f"Passive scanning {base_url}")
            
            # Wait for passive scanning to complete
            while int(self.zap.pscan.records_to_scan) > 0:
                logger.info(f"Remaining records to scan: {self.zap.pscan.records_to_scan}")
                time.sleep(2)
        
        logger.info("Passive scan completed")
    
    def run_active_scan(self):
        """Run active scanning"""
        logger.info("Running active scan...")
        
        # Skip if ZAP is not available or if skip_zap is enabled
        if self.zap is None or self.skip_zap:
            logger.warning("ZAP is not available or skipped. Skipping active scan.")
            return
            
        # Enable all scanners
        self.zap.ascan.enable_all_scanners()
        
        # Configure scan policy
        scan_policy = 'API-Security-Policy'
        try:
            logger.info("Checking for existing ZAP scan policy")
            policy_names = self.zap.ascan.scan_policy_names
            if scan_policy not in policy_names:
                logger.warning(f"Scan policy '{scan_policy}' not found. Creating a new policy...")
                self.zap.ascan.add_scan_policy(
                    scanpolicyname=scan_policy,
                    alertthreshold='Medium',
                    attackstrength='Medium'
                )
            else:
                 logger.info(f"Using existing scan policy '{scan_policy}'")
        except Exception as e:
            logger.error(f"Failed to configure ZAP scan policy: {e}. Proceeding without custom policy.")
            scan_policy = 'Default Policy' # Fallback to default if configuration fails
        
        scan_ids = []
        default_context_name = 'Default Context'
        default_context_id = None
        userId = None # Assuming default user for context scan

        # Get Default Context ID
        try:
            contexts = self.zap.context.context_list
            if default_context_name in contexts:
                 context_details = self.zap.context.context(default_context_name)
                 default_context_id = context_details['id']
                 logger.info(f"Found '{default_context_name}' with ID: {default_context_id}")
                 # Attempt to find a user ID within the context for authenticated scanning if needed
                 # This part might need adjustment based on actual authentication setup
                 try:
                    users = self.zap.users.users_list(contextid=default_context_id)
                    if users:
                        userId = users[0]['id'] # Use the first user found
                        logger.info(f"Using User ID {userId} for authenticated scan in context {default_context_id}")
                 except Exception as user_error:
                    logger.warning(f"Could not retrieve users for context {default_context_id}: {user_error}. Scan might be unauthenticated.")
                 except Exception as user_ex:
                    logger.warning(f"Unexpected error retrieving users for context {default_context_id}: {user_ex}. Scan might be unauthenticated.")
            else:
                 logger.warning(f"Could not find ZAP context named '{default_context_name}'. Creating it.")
                 try:
                     default_context_id = self.zap.context.new_context(default_context_name)
                     logger.info(f"Created new context '{default_context_name}' with ID: {default_context_id}")
                     # Include the base URL from the first endpoint as a starting point for the context
                     if self.api_endpoints:
                         base_url = urlparse(self.api_endpoints[0]['url']).scheme + "://" + urlparse(self.api_endpoints[0]['url']).netloc
                         self.zap.context.include_in_context(default_context_name, re.escape(base_url) + '.*')
                         logger.info(f"Included base URL pattern {re.escape(base_url)}.* in context {default_context_name}")
                 except Exception as create_error:
                     logger.error(f"Failed to create new context '{default_context_name}': {create_error}")
                     default_context_id = None # Ensure it's None if creation failed
                 except Exception as create_ex:
                      logger.error(f"Unexpected error creating new context '{default_context_name}': {create_ex}")
                      default_context_id = None

        except Exception as e:
            logger.error(f"Failed to get/create ZAP contexts: {e}")
        except Exception as e:
             logger.error(f"Unexpected error getting/creating ZAP contexts: {e}")

        # Proceed with scan only if context ID is valid
        if default_context_id:
            logger.info(f"Starting active scan on context ID {default_context_id} with policy '{scan_policy}'")
            scan_id_str = self.zap.ascan.scan(contextid=default_context_id, scanpolicyname=scan_policy)
            self.active_scan_id = scan_id_str # Store the scan ID
            logger.info(f"Started active scan for context {default_context_id} with ID: {scan_id_str}")

            # Monitor scan progress
            while True:
                status_str = self.zap.ascan.status(self.active_scan_id)
                if not status_str.isdigit():
                    logger.error(f"Failed to get valid status for scan ID {self.active_scan_id} (Context: {default_context_id}). ZAP returned: {status_str}")
                    break
                progress = int(status_str)
                if progress >= 100:
                    logger.info(f"Scan {self.active_scan_id} (Context: {default_context_id}) completed.")
                    break
                logger.info(f"Scan {self.active_scan_id} (Context: {default_context_id}) progress: {progress}%")
                time.sleep(10) # Increased sleep time for context scan

            logger.info("Active scan phase completed.")

    def run_api_fuzzing(self):
        """Run API fuzzing tests"""
        logger.info("Running API fuzzing tests...")
        
        fuzzing_results = []
        test_payloads = {
            "SQL Injection": ["'", "1' OR '1'='1", "1; DROP TABLE users"],
            "Command Injection": ["; ls -la", "& ping 127.0.0.1", "| cat /etc/passwd"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "SSRF": ["http://localhost", "file:///etc/passwd", "http://169.254.169.254/"],
            "Path Traversal": ["../../../etc/passwd", "..\\..\\Windows\\win.ini"],
            "Parameter Tampering": ["", "null", "true", "false", "{}", "[]", "-1"]
        }
        
        # Determine if we should route through ZAP
        use_zap_proxy = self.zap is not None and not self.skip_zap
        
        for endpoint in self.api_endpoints:
            logger.info(f"Fuzzing {endpoint['name']}")
            
            # Parse the request body
            try:
                request_body = json.loads(endpoint['body'])
            except:
                request_body = {}
            
            # Test each parameter with payloads
            for param, value in self._flatten_json(request_body):
                for attack_type, payloads in test_payloads.items():
                    for payload in payloads:
                        # Create a modified request body with the payload
                        modified_body = self._set_nested_value(
                            request_body.copy(), 
                            param.split('.'), 
                            payload
                        )
                        
                        # Make request with modified body
                        try:
                            headers = {h['key']: h['value'] for h in endpoint['headers']}
                            if self.api_key:
                                headers['x-api-key'] = self.api_key
                            
                            # Set up request parameters
                            request_params = {
                                'url': endpoint['url'],
                                'headers': headers,
                                'json': modified_body,
                                'timeout': 10,
                                'verify': False  # WARNING: Disables SSL verification
                            }
                            
                            # Add proxy if ZAP is available
                            request_proxies = {"http": f"http://{self.zap_host}:{self.zap_port}", "https": f"http://{self.zap_host}:{self.zap_port}"} if use_zap_proxy else None
                            request_params['proxies'] = request_proxies
                            
                            response = requests.post(**request_params)

                            # Check for potential vulnerabilities based on response
                            issue = self._analyze_fuzzing_response(
                                endpoint, param, payload, attack_type, response
                            )
                            if issue:
                                fuzzing_results.append(issue)
                                
                        except Exception as e:
                            logger.warning(f"Error during fuzzing: {e}")
        
        self.scan_results['fuzzing'] = fuzzing_results
        logger.info(f"Fuzzing tests completed with {len(fuzzing_results)} findings")
    
    def _flatten_json(self, json_obj, parent_key=''):
        """Flatten a nested JSON object"""
        items = []
        for k, v in json_obj.items() if isinstance(json_obj, dict) else enumerate(json_obj):
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, (dict, list)):
                items.extend(self._flatten_json(v, new_key))
            else:
                items.append((new_key, v))
        return items
    
    def _set_nested_value(self, obj, keys, value):
        """Set a value in a nested dictionary using a list of keys"""
        if len(keys) == 1:
            if isinstance(obj, dict):
                obj[keys[0]] = value
            elif isinstance(obj, list) and keys[0].isdigit():
                idx = int(keys[0])
                if idx < len(obj):
                    obj[idx] = value
            return obj
        
        if isinstance(obj, dict) and keys[0] in obj:
            obj[keys[0]] = self._set_nested_value(obj[keys[0]], keys[1:], value)
        elif isinstance(obj, list) and keys[0].isdigit():
            idx = int(keys[0])
            if idx < len(obj):
                obj[idx] = self._set_nested_value(obj[idx], keys[1:], value)
        
        return obj
    
    def _analyze_fuzzing_response(self, endpoint, param, payload, attack_type, response):
        """Analyze fuzzing response for potential vulnerabilities"""
        # Check for error messages that might indicate vulnerabilities
        error_indicators = {
            "SQL Injection": ["sql syntax", "SQL syntax", "mysql", "sql error", "ORA-"],
            "Command Injection": ["permission denied", "command not found", "sh:", "bash:"],
            "Path Traversal": ["No such file", "cannot find the file", "root:"],
            "SSRF": ["Connection refused", "timeout", "certificate", "metadata"]
        }
        
        response_text = response.text.lower()
        for error_type, indicators in error_indicators.items():
            if attack_type == error_type and any(i.lower() in response_text for i in indicators):
                return {
                    "endpoint": endpoint['name'],
                    "url": endpoint['url'],
                    "method": endpoint['method'],
                    "parameter": param,
                    "attack_type": attack_type,
                    "payload": payload,
                    "response_code": response.status_code,
                    "evidence": next((i for i in indicators if i.lower() in response_text), ""),
                    "severity": "High"
                }
        
        # Check for successful injection based on status code anomalies
        if response.status_code >= 500:
            return {
                "endpoint": endpoint['name'],
                "url": endpoint['url'],
                "method": endpoint['method'],
                "parameter": param,
                "attack_type": attack_type,
                "payload": payload,
                "response_code": response.status_code,
                "evidence": "Server error triggered by payload",
                "severity": "Medium"
            }
        
        return None
    
    def analyze_authentication(self):
        """Analyze authentication mechanism"""
        logger.info("Analyzing authentication mechanism...")
        
        auth_issues = []
        
        # Check for x-api-key usage
        uses_api_key = any(
            any(h['key'].lower() == 'x-api-key' for h in endpoint['headers'])
            for endpoint in self.api_endpoints
        )
        
        if uses_api_key:
            auth_issues.append({
                "issue": "API Key Authentication",
                "description": "Using API key for authentication. Ensure API keys are properly secured, rotated periodically, and have appropriate access controls.",
                "recommendation": "Consider implementing OAuth 2.0 or JWT for more robust authentication.",
                "severity": "Medium"
            })
        
        self.scan_results['authentication'] = auth_issues
        logger.info(f"Authentication analysis completed with {len(auth_issues)} findings")
    
    def analyze_tls_security(self):
        """Analyze TLS security of endpoints"""
        logger.info("Analyzing TLS security...")
        
        tls_issues = []
        
        # Determine if we should route through ZAP
        use_zap_proxy = self.zap is not None and not self.skip_zap

        for endpoint in self.api_endpoints:
            url = endpoint.get('url')
            if not url:
                logger.warning(f"Skipping TLS analysis for endpoint {endpoint.get('name')} - No URL found")
                continue
                
            if url.startswith('https://'):
                try:
                    # Use requests to check TLS
                    # Use ssl module for a more reliable TLS check
                    hostname = url.split('/')[2] if len(url.split('/')) > 2 else None
                    if not hostname:
                        logger.warning(f"Invalid URL format for endpoint {endpoint.get('name')}: {url}")
                        continue
                    port = 443 # Assume default HTTPS port
                    if ':' in hostname:
                        hostname, port_str = hostname.split(':')
                        port = int(port_str)

                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port)) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            tls_version = ssock.version()
                            if tls_version in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                                tls_issues.append({
                                    "endpoint": endpoint['name'],
                                    "url": url,
                                    "issue": "Outdated TLS Version",
                                    "description": f"Endpoint supports {tls_version} which is considered insecure.",
                                    "recommendation": "Disable insecure TLS/SSL versions. Configure server to use TLS 1.2 or TLS 1.3 only.",
                                    "severity": "High"
                                })
                            # Could add cipher checks here too
                            # logger.info(f"TLS check for {url}: Version={tls_version}, Cipher={ssock.cipher()}")

                except ssl.SSLError as e:
                     logger.warning(f"SSL Error checking TLS for {url}: {e}")
                     tls_issues.append({
                         "endpoint": endpoint['name'], "url": url, "issue": "SSL/TLS Handshake Error",
                         "description": f"Could not establish secure connection: {e}",
                         "recommendation": "Investigate server TLS configuration and certificate validity.",
                         "severity": "High"
                     })
                except socket.gaierror as e:
                     logger.warning(f"DNS Resolution Error checking TLS for {url}: {e}")
                except ConnectionRefusedError as e:
                     logger.warning(f"Connection Refused checking TLS for {url}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error checking TLS for {url}: {e}", exc_info=True)
        
        self.scan_results['tls'] = tls_issues
        logger.info(f"TLS security analysis completed with {len(tls_issues)} findings")
    
    def analyze_rate_limiting(self):
        """Analyze rate limiting configuration"""
        logger.info("Analyzing rate limiting...")
        
        rate_limit_issues = []
        
        # Determine if we should route through ZAP
        use_zap_proxy = self.zap is not None and not self.skip_zap
        
        # Test for rate limiting by making multiple requests
        for endpoint in self.api_endpoints:
            url = endpoint['url']
            headers = {h['key']: h['value'] for h in endpoint['headers']}
            if self.api_key:
                headers['x-api-key'] = self.api_key
            
            # Make several rapid requests to test rate limiting
            responses = []
            for _ in range(5):
                try:
                    # Set up request parameters
                    request_params = {
                        'url': url,
                        'headers': headers,
                        'json': json.loads(endpoint['body']),
                        'timeout': 5,
                        'verify': False  # WARNING: Disables SSL verification
                    }
                    
                    # Add proxy if ZAP is available
                    request_proxies = {"http": f"http://{self.zap_host}:{self.zap_port}", "https": f"http://{self.zap_host}:{self.zap_port}"} if use_zap_proxy else None
                    request_params['proxies'] = request_proxies
                    
                    response = requests.post(**request_params)
                    responses.append(response)
                    time.sleep(0.5)  # Short delay between requests
                except Exception as e:
                    logger.warning(f"Error during rate limit testing: {e}")
            
            # Check responses for rate limiting headers/status codes
            if responses:  # Only check if we have valid responses
                rate_limited = any(
                    r.status_code == 429 or 
                    'x-rate-limit' in r.headers or 
                    'retry-after' in r.headers
                    for r in responses
                )
                
                if not rate_limited:
                    rate_limit_issues.append({
                        "endpoint": endpoint['name'],
                        "url": url,
                        "issue": "No Rate Limiting Detected",
                        "description": "Endpoint does not appear to implement rate limiting, which could lead to DoS attacks",
                        "recommendation": "Implement rate limiting with appropriate headers (X-Rate-Limit, Retry-After)",
                        "severity": "Medium"
                    })
            else:
                logger.warning(f"Could not test rate limiting for {endpoint['name']} due to connection errors")
        
        self.scan_results['rate_limiting'] = rate_limit_issues
        logger.info(f"Rate limiting analysis completed with {len(rate_limit_issues)} findings")
    
    def collect_zap_results(self):
        """Collect and process results from ZAP"""
        if not self.zap:
            logger.warning("ZAP not available, skipping result collection.")
            return

        logger.info("Collecting results from ZAP...")
        try:
            alerts = self.zap.core.alerts()
            self.vulnerabilities.extend(alerts) # Add full alert dictionaries
            logger.info(f"Collected {len(alerts)} issues from ZAP")
        except Exception as e:
            logger.error(f"Failed to collect results from ZAP: {e}")
        except Exception as e:
            logger.error(f"Unexpected error collecting results from ZAP: {e}")

    def map_to_owasp_api_top10(self):
        """Map vulnerabilities to OWASP API Top 10"""
        logger.info("Mapping issues to OWASP API Top 10...")
        
        # Define mapping rules
        mapping_rules = {
            "API1:2023": ["authorization", "access control", "IDOR"],
            "API2:2023": ["authentication", "login", "session", "jwt", "oauth"],
            "API3:2023": ["property", "level authorization", "mass assignment"],
            "API4:2023": ["resource", "consumption", "rate limit", "dos", "ddos"],
            "API5:2023": ["function level", "unauthorized function", "improper authorization"],
            "API6:2023": ["business flow", "business logic", "workflow"],
            "API7:2023": ["ssrf", "server side request forgery"],
            "API8:2023": ["misconfiguration", "default credential", "unnecessary feature", "cors"],
            "API9:2023": ["inventory", "documentation", "swagger", "outdated"],
            "API10:2023": ["deserialization", "parsing", "validation", "sanitization"]
        }
        
        # Collect all issues
        all_issues = []
        for category, issues in self.scan_results.items():
            for issue in issues:
                issue_text = json.dumps(issue).lower()
                owasp_categories = []
                
                for category, keywords in mapping_rules.items():
                    if any(keyword.lower() in issue_text for keyword in keywords):
                        owasp_categories.append(category)
                
                # Default to API8 if no mapping found
                if not owasp_categories:
                    owasp_categories = ["API8:2023"]
                
                issue["owasp_api_categories"] = owasp_categories
                all_issues.append(issue)
        
        self.scan_results['all_mapped'] = all_issues
        
        # Count issues by OWASP category
        owasp_counts = {cat: 0 for cat in OWASP_API_TOP_10.keys()}
        for issue in all_issues:
            for cat in issue.get("owasp_api_categories", []):
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        
        self.scan_results['owasp_counts'] = owasp_counts
        logger.info("OWASP API Top 10 mapping completed")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        logger.info("Generating security report...")
        
        # Create timestamp for report
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"{REPORT_DIR}/api_security_report_{timestamp}.html"
        
        # Generate graphs
        self._generate_graphs()
        
        # Prepare template data
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = Counter(alert.get('riskString', 'Unknown') for alert in self.vulnerabilities)
        owasp_counts = Counter(alert.get('owasp_api_top10', 'Unmapped') for alert in self.vulnerabilities)
        
        # Base64 encode logo
        logo_base64 = None
        logo_path = "CoinDCX.png" # Assumes logo is in the same directory as the script
        try:
            if os.path.exists(logo_path):
                with open(logo_path, "rb") as image_file:
                    logo_base64 = base64.b64encode(image_file.read()).decode('utf-8')
                logger.info(f"Successfully encoded logo from {logo_path}")
            else:
                 logger.warning(f"Logo file not found at {logo_path}")
        except Exception as e:
            logger.error(f"Error reading or encoding logo file {logo_path}: {e}")

        context_data = {
            'report_title': "API Security Assessment Report",
            'report_time': report_time,
            'target_info': {
                 'zap_host': self.zap_host,
                 'zap_port': self.zap_port,
                 'collection_file': self.collection.get('info', {}).get('name', 'N/A'),
                 'endpoints_tested_count': len(self.api_endpoints),
            },
            'scan_summary': {
                'passive_scan_status': 'Completed', # Assuming it runs if ZAP is up
                'active_scan_status': 'Completed' if self.active_scan_id is not None else 'Skipped/Failed', # Check self.active_scan_id
                'fuzzing_status': 'Completed', # Add more detail later if needed
            },
            'vulnerabilities': self.vulnerabilities,
            'severity_counts': dict(severity_counts),
            'owasp_counts': dict(owasp_counts),
            'endpoints': self.api_endpoints, # Pass endpoint list
            'severity_plot_path': os.path.join(REPORT_DIR, 'severity_distribution.png'), 
            'owasp_plot_path': os.path.join(REPORT_DIR, 'owasp_distribution.png'),
            'logo_base64': logo_base64
        }
        
        # Get and render template
        template_str = self._get_report_template()
        template = Template(template_str)
        report_html = template.render(**context_data)
        
        with open(report_file, 'w') as f:
            f.write(report_html)
        
        logger.info(f"Security report generated: {report_file}")
        return report_file
    
    def _get_report_template(self):
        """Get HTML template for the report"""
        # Improved HTML template with more details and logo
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_title }}</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        .container { background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 5px; }
        h1 { text-align: center; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #007bff; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .severity-high { color: red; font-weight: bold; }
        .severity-medium { color: orange; font-weight: bold; }
        .severity-low { color: blue; }
        .severity-informational { color: grey; }
        .logo { max-width: 150px; height: auto; display: block; margin: 0 auto 20px auto; }
        .summary-section, .details-section { margin-bottom: 30px; }
        .code { background-color: #e9e9e9; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
        .details { margin-top: 5px; padding-left: 15px; border-left: 3px solid #ccc; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        {% if logo_base64 %}
            <img src="data:image/png;base64,{{ logo_base64 }}" alt="Logo" class="logo">
        {% else %}
             <p style="text-align:center; font-style:italic;">Logo not found or could not be loaded.</p>
        {% endif %}
        <h1>{{ report_title }}</h1>
        <p>Generated on: {{ report_time }}</p>

        <div class="summary-section">
            <h2>Executive Summary</h2>
            <p>This report details the findings of the security assessment performed on the target APIs.</p>
            <table>
                <tr><th>Category</th><th>Details</th></tr>
                <tr><td>Target Collection</td><td>{{ target_info.collection_file }}</td></tr>
                <tr><td>ZAP Instance</td><td>{{ target_info.zap_host }}:{{ target_info.zap_port }}</td></tr>
                <tr><td>Endpoints Found</td><td>{{ target_info.endpoints_tested_count }}</td></tr>
                <tr><td>Passive Scan</td><td>{{ scan_summary.passive_scan_status }}</td></tr>
                <tr><td>Active Scan</td><td>{{ scan_summary.active_scan_status }}</td></tr>
                <tr><td>API Fuzzing</td><td>{{ scan_summary.fuzzing_status }}</td></tr>
            </table>
            <h3>Findings Summary by Severity</h3>
            <img src="severity_distribution.png" alt="Severity Distribution Chart" style="max-width:100%; height:auto;">
             <ul>
                {% for severity, count in severity_counts.items() %}
                    <li>{{ severity }}: {{ count }}</li>
                {% endfor %}
            </ul>
            <h3>Findings Summary by OWASP API Top 10 (2023)</h3>
            <table>
                <tr><th>OWASP API Top 10 Category</th><th>Count</th></tr>
                {% for category, count in owasp_counts.items() %}
                    <tr><td>{{ category }}</td><td>{{ count }}</td></tr>
                {% else %}
                    <tr><td colspan="2">No vulnerabilities mapped to OWASP API Top 10.</td></tr>
                {% endfor %}
            </table>
            <img src="owasp_distribution.png" alt="OWASP API Top 10 Distribution Chart" style="max-width:100%; height:auto;">
            <ul>
                {% for category, count in owasp_counts.items() %}
                    <li>{{ category }}: {{ count }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="details-section">
            <h2>Tested API Endpoints</h2>
            <table>
                 <tr><th>Method</th><th>URL</th><th>Description</th></tr>
                 {% for endpoint in endpoints %}
                    <tr>
                        <td>{{ endpoint.method }}</td>
                        <td>{{ endpoint.url }}</td>
                        <td>{{ endpoint.name }}</td>
                    </tr>
                 {% else %}
                    <tr><td colspan="3">No endpoints extracted.</td></tr>
                 {% endfor %}
            </table>
        </div>
        
        <div class="details-section">
            <h2>Detailed Findings</h2>
            {% if vulnerabilities %}
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Risk</th>
                        <th>Confidence</th>
                        <th>URL</th>
                        <th>Details</th>
                    </tr>
                    {% for alert in vulnerabilities %}
                        <tr>
                            <td>{{ alert.alertId }}</td>
                            <td>{{ alert.name }}</td>
                            <td class="severity-{{ alert.riskString | lower }}">{{ alert.riskString }}</td>
                            <td>{{ alert.confidenceString }}</td>
                            <td>{{ alert.url }}</td>
                            <td>
                                {% if alert.description %}<p><strong>Description:</strong> {{ alert.description }}</p>{% endif %}
                                {% if alert.param %}<p><strong>Parameter:</strong> <span class="code">{{ alert.param }}</span></p>{% endif %}
                                {% if alert.attack %}<p><strong>Attack:</strong> <span class="code">{{ alert.attack }}</span></p>{% endif %}
                                {% if alert.evidence %}<p><strong>Evidence:</strong> <span class="code">{{ alert.evidence }}</span></p>{% endif %}
                                {% if alert.solution %}<p><strong>Solution:</strong> {{ alert.solution }}</p>{% endif %}
                                {% if alert.reference %}<p><strong>Reference:</strong> <a href="{{ alert.reference }}" target="_blank">Link</a></p>{% endif %}
                                {% if alert.cweid %}<p><strong>CWE ID:</strong> {{ alert.cweid }}</p>{% endif %}
                                {% if alert.wascid %}<p><strong>WASC ID:</strong> {{ alert.wascid }}</p>{% endif %}
                                {% if alert.owasp_api_top10 %}<p><strong>OWASP API Top 10 (2023):</strong> {{ alert.owasp_api_top10 }}</p>{% endif %}
                            </td>
                        </tr>
                    {% endfor %}
                </table>
            {% else %}
                <p>No vulnerabilities found by ZAP.</p>
            {% endif %}
        </div>

        <div class="footer">
            <p>End of Report</p>
        </div>
    </div>
</body>
</html>
"""

    def _generate_graphs(self):
        """Generate graphs for the report"""
        # Create severity distribution pie chart
        severity_counts = Counter(alert.get('riskString', 'Unknown') for alert in self.vulnerabilities)
        
        plt.figure(figsize=(10, 6))
        plt.pie(
            severity_counts.values(), 
            labels=severity_counts.keys(),
            autopct='%1.1f%%', 
            startangle=90,
            colors=['#ff6b6b', '#feca57', '#1dd1a1']
        )
        plt.title('Vulnerability Severity Distribution')
        plt.tight_layout()
        plt.savefig(f"{REPORT_DIR}/severity_distribution.png")
        plt.close()
        
        # Create OWASP API Top 10 distribution bar chart
        owasp_counts = Counter(alert.get('owasp_api_top10', 'Unmapped') for alert in self.vulnerabilities)
        
        plt.figure(figsize=(12, 8))
        sns.barplot(
            x=list(owasp_counts.keys()),
            y=list(owasp_counts.values()),
            palette='viridis'
        )
        plt.xticks(rotation=45, ha='right')
        plt.title('OWASP API Top 10 Vulnerability Distribution')
        plt.xlabel('OWASP API Category')
        plt.ylabel('Number of Issues')
        plt.tight_layout()
        plt.savefig(f"{REPORT_DIR}/owasp_distribution.png")
        plt.close()
    
    def run_assessment(self):
        """Run the complete security assessment"""
        logger.info("Starting API security assessment...")
        
        # 1. Extract API endpoints
        self.extract_endpoints()
        
        # 2. Start OWASP ZAP
        try:
            self.start_zap()
            zap_available = True
        except SystemExit:
            logger.warning("OWASP ZAP is not available. Continuing with limited functionality.")
            logger.warning("Some security tests that require ZAP will be skipped.")
            zap_available = False
        
        # Only run ZAP-dependent steps if ZAP is available
        if zap_available:
            # 3. Import endpoints to ZAP
            self.import_to_zap()
            
            # 4. Configure authentication
            self.configure_authentication()
            
            # 5. Run passive scan
            self.run_passive_scan()
            
            # 6. Run active scan
            self.run_active_scan()
        
        # 7. Run API fuzzing (modified to work without ZAP if needed)
        self.run_api_fuzzing()
        
        # 8. Analyze authentication
        self.analyze_authentication()
        
        # 9. Analyze TLS security
        self.analyze_tls_security()
        
        # 10. Analyze rate limiting
        self.analyze_rate_limiting()
        
        # 11. Collect ZAP results
        self.collect_zap_results()
        
        # 12. Map to OWASP API Top 10
        self.map_to_owasp_api_top10()
        
        # 13. Generate report
        report_file = self.generate_report()
        
        logger.info(f"Security assessment completed. Report generated: {report_file}")
        return report_file


def main():
    """Main function to run the assessment"""

    # Unset proxy env vars for this script's requests
    os.environ.pop('HTTP_PROXY', None)
    os.environ.pop('HTTPS_PROXY', None)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)

    parser = argparse.ArgumentParser(description='API Security Assessment Script')
    parser.add_argument('--collection', required=True, help='Path or JSON string of the Postman collection')
    parser.add_argument('--api-key', help='API key for authentication (if required by the target API)')
    parser.add_argument('--zap-path', help='Path to the ZAP executable (e.g., /path/to/zap.sh or C:\\path\\to\\zap.bat)')
    parser.add_argument('--skip-zap', action='store_true', help='Skip ZAP integration and scanning')
    parser.add_argument('--zap-host', default='localhost', help='OWASP ZAP host (default: localhost)')
    parser.add_argument('--zap-port', type=int, default=8080, help='OWASP ZAP port (default: 8080)')
    parser.add_argument('--zap-key', help='OWASP ZAP API key (required if ZAP API key is enabled)')

    args = parser.parse_args()

    # Check if ZAP key is provided if ZAP is not skipped
    if not args.skip_zap and not args.zap_key:
        logger.warning("ZAP API key (--zap-key) not provided. ZAP connection might fail if the API key is enabled in ZAP.")
        logger.warning("You can find/set the ZAP API key in ZAP -> Tools -> Options -> API")

    logger.info("Starting API Security Assessment...")

    assessment = APISecurityAssessment(
        postman_collection=args.collection,
        zap_host=args.zap_host,
        zap_port=args.zap_port,
        api_key=args.zap_key,
        zap_path=args.zap_path,
        skip_zap=args.skip_zap
    )
    assessment.run_assessment()

    logger.info("Assessment completed. Report generated in security_report directory.")


if __name__ == "__main__":
    main()
