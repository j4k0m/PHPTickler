import os, re, json, threading, queue, requests, ast, argparse, sys, html, datetime
from typing import List, Dict, Set, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from colorama import init, Fore, Style
from pathlib import Path

class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

@dataclass
class VulnerabilityResult:
    type: str
    severity: SeverityLevel
    line_number: int
    line_content: str
    function: str
    description: str
    remediation: str
    cwe_id: str
    references: List[str]
    owasp_category: str = None
    fix_snippet: str = None
    framework: str = None

@dataclass
class TaintSource:
    source_type: str
    match: str
    line_number: int
    content: str = ''

@dataclass
class TaintSink:
    sink_type: str
    match: str
    line_number: int
    content: str = ''

class VulnerabilityScanner(ABC):
    @abstractmethod
    def scan(self, content: str) -> List[VulnerabilityResult]:
        pass

class StaticAnalysisScanner(VulnerabilityScanner):
    def __init__(self):
        self.sql_injection_sinks = [
            r'SELECT.*FROM.*WHERE.*=\s*[\'"]\s*\$(?:_GET|_POST|REQUEST)',
            r'SELECT.*FROM.*WHERE.*=\s*\$(?!_SERVER)[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*',
            r'SELECT.*FROM.*WHERE.*=\s*[\'"]\s*\$.*[\'"]',
            r'SELECT.*FROM.*WHERE.*=\s*\$.*(?<!escaped_)',
            r'mysqli_query\s*\([^,]+,\s*[\'"][^\'"].*\$.*[\'"]',
            r'mysqli_query\s*\([^,]+,\s*\$.*\)',
            r'mysql_query\s*\([\'"][^\'"].*\$.*[\'"]',
            r'\$.*->query\s*\([\'"][^\'"].*\$.*[\'"]'
        ]

        self.rce_sinks = [
            r'system\s*\([^)]*\$',
            r'exec\s*\([^)]*\$',
            r'shell_exec\s*\([^)]*\$',
            r'passthru\s*\([^)]*\$',
            r'`.*\$.*`',
            r'popen\s*\([^)]*\$',
            r'proc_open\s*\([^)]*\$',
            r'eval\s*\([^)]*\$',
            r'assert\s*\([^)]*\$',
            r'create_function\s*\([^)]*\$'
        ]

        self.xss_sinks = [
            r'echo\s+[^;]*\$_(?:GET|POST|REQUEST)',
            r'echo\s+[^;]*\$(?!_SERVER)[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*',
            r'print\s+[^;]*\$_(?:GET|POST|REQUEST)',
            r'print\s+[^;]*\$(?!_SERVER)[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*',
            r'<.*?>\s*\$.*?</.*?>',
            r'innerHTML\s*=\s*[\'"].*?\$' 
        ]

        self.file_upload_sinks = [
            r'move_uploaded_file\s*\(',
            r'\$_FILES\s*\[',
            r'copy\s*\([^,]*\$_FILES',
            r'file_put_contents\s*\([^,]*\$_FILES',
            r'fwrite\s*\([^,]*\$_FILES'
        ]

        self.lfi_sinks = [
            r'include\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'require\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'include_once\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'require_once\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'file_get_contents\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'fopen\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'readfile\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'file\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)'
        ]

        self.safe_sanitization = {
            'sql': [
                r'mysqli_real_escape_string',
                r'mysql_real_escape_string',
                r'PDO::prepare',
                r'mysqli_prepare',
                r'bind_param'
            ],
            'xss': [
                r'htmlspecialchars\s*\(',
                r'htmlentities\s*\(',
                r'strip_tags\s*\('
            ],
            'file': [
                r'pathinfo\s*\(',
                r'filesize\s*\(',
                r'mime_content_type\s*\(',
                r'is_uploaded_file\s*\('
            ],
            'path': [
                r'basename\s*\(',
                r'realpath\s*\(',
                r'dirname\s*\('
            ]
        }

        self.dangerous_extensions = [
            r'\.php',
            r'\.phtml',
            r'\.php3',
            r'\.php4',
            r'\.php5',
            r'\.php7',
            r'\.pht',
            r'\.phar',
            r'\.exe',
            r'\.sh',
            r'\.asp',
            r'\.aspx',
            r'\.jsp',
            r'\.cgi'
        ]

        self.path_traversal_sinks = [
            r'(?:fopen|file_get_contents|file_put_contents|readfile)\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST|_FILES)',
            r'(?:opendir|scandir|dir)\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST|_FILES)',
            r'(?:include|require|include_once|require_once)\s*\(\s*[\'"]?\$(?:_GET|_POST|REQUEST)',
            r'move_uploaded_file\s*\(\s*\$_FILES.*?,\s*(?:[\'"].*?\$(?:_GET|_POST|REQUEST)|[^,]*?\.\.)',
            r'[\'"](?:\.\./|\.\.\\\|\.\/|\.\\)+.*?\$(?:_GET|_POST|REQUEST)',
            r'\$(?:path|dir|directory|file|filename)\s*=\s*[\'"].*?\$(?:_GET|_POST|REQUEST)',
            r'\$target(?:_dir|_path|_file)\s*=\s*[\'"].*?\$(?:_GET|_POST|REQUEST)',
            r'basename\s*\(\s*\$(?:_GET|_POST|REQUEST)\[.*?\]',
            r'realpath\s*\(\s*\$(?:_GET|_POST|REQUEST)\[.*?\]'
        ]
        self.safe_path_patterns = [
            r'<link[^>]+href=[\'"]\.\./',
            r'<script[^>]+src=[\'"]\.\./',
            r'<img[^>]+src=[\'"]\.\./',
            r'href=[\'"]\.\./',
            r'location\.href=[\'"]\.\./\w+',
            r'onclick=[\'"]location\.href=[\'"]\.\./\w+'
        ]

        self.path_traversal_sanitization = [
            r'realpath\s*\(',
            r'basename\s*\(',
            r'dirname\s*\(',
            r'pathinfo\s*\(',
            r'str_replace\s*\(\s*[\'"]\.\.[\'"]\s*,\s*[\'"][\'"]\s*,',
            r'strstr\s*\([^,]+,\s*[\'"]\.\.[\'"]\s*\)\s*===\s*false',
            r'strpos\s*\([^,]+,\s*[\'"]\.\.[\'"]\s*\)\s*===\s*false',
            r'preg_replace\s*\(\s*[\'"](?:#|/)\.\./[\'"]',
            r'(?:DIRECTORY_SEPARATOR|PATH_SEPARATOR)',
            r'is_dir\s*\(',
            r'is_file\s*\(',
            r'file_exists\s*\('
        ]

        self.path_traversal_sinks = [
            r'move_uploaded_file\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]tmp_name[\'"]\]\s*,\s*(?:[^,]*?\.\.|\$(?:_GET|_POST|REQUEST|_FILES))',
            r'\$target(?:_dir|_file|_path)\s*=\s*[\'"].*?\$_FILES\[[\'"].*?[\'"]\]\[[\'"]name[\'"]\]',
            r'basename\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]name[\'"]\]\s*\)',
            r'[\'"]uploads\/[\'"]?\s*\.\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]name[\'"]\]',
            r'[\'"]uploads\/[\'"]?\s*\.\s*basename\s*\(\s*\$_FILES',
            r'(?<!realpath\()(?<!is_uploaded_file\()\$_FILES\[[\'"].*?[\'"]\]\[[\'"](?:name|tmp_name)[\'"]\]',
            r'\$target.*?=.*?[\'"].*?\/.*?\$_FILES',
            r'pathinfo\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]name[\'"]\]\s*\)',
            r'(?<!realpath\()\$target_(?:dir|file|path)\s*=\s*[\'"].*?\/.*?\$'
        ]

        self.file_upload_sanitization = [
            r'is_uploaded_file\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]tmp_name[\'"]\]\s*\)',
            r'realpath\s*\(\s*\$target(?:_dir|_file|_path)\s*\)',
            r'pathinfo\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]name[\'"]\]\s*,\s*PATHINFO_(?:BASENAME|EXTENSION)\s*\)',
            r'mime_content_type\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]tmp_name[\'"]\]\s*\)',
            r'getimagesize\s*\(\s*\$_FILES\[[\'"].*?[\'"]\]\[[\'"]tmp_name[\'"]\]\s*\)'
        ]

    def _check_vulnerability(self, line: str, line_number: int, patterns: List[str], 
                           vuln_type: str, severity: SeverityLevel, 
                           cwe_id: str, variables: Dict) -> Optional[VulnerabilityResult]:
        for pattern in patterns:
            if re.search(pattern, line):
                is_vulnerable = False
                used_var = None

                if re.search(r'\$_(?:GET|POST|REQUEST)', line):
                    is_vulnerable = True
                else:
                    for var in variables:
                        if f'${var}' in line:
                            used_var = variables[var]
                            if not used_var.get(f'{vuln_type.lower()}_sanitized', False):
                                is_vulnerable = True
                                break

                if is_vulnerable:
                    return self._create_vulnerability_result(
                        vuln_type, severity, line_number, line, used_var, cwe_id
                    )
        return None

    def _create_vulnerability_result(self, vuln_type: str, severity: SeverityLevel, 
                                   line_number: int, line: str, var_info: Optional[dict], 
                                   cwe_id: str) -> VulnerabilityResult:
        vuln = VulnerabilityResult(
            type=vuln_type,
            severity=severity,
            line_number=line_number,
            line_content=line.strip(),
            function="",
            description=f"Potential {vuln_type} vulnerability detected",
            remediation=f"Please review and secure the {vuln_type.lower()} implementation",
            cwe_id=cwe_id,
            references=["https://owasp.org/www-project-top-ten/"],
            owasp_category="A03:2021-Injection"
        )
        
        print(f"Created vulnerability: {vuln_type} on line {line_number}")
        return vuln

    def scan(self, content: str) -> List[VulnerabilityResult]:
        vulnerabilities = []
        lines = content.split('\n')
        variables = self._track_variables(lines)
        
        file_operations = self._track_file_operations(lines)
        
        for i, line in enumerate(lines, 1):
            if vuln := self._check_vulnerability(line, i, self.sql_injection_sinks, 
                                               "SQL Injection", SeverityLevel.CRITICAL, 
                                               "CWE-89", variables):
                vulnerabilities.append(vuln)

            if vuln := self._check_vulnerability(line, i, self.rce_sinks, 
                                               "Remote Code Execution", SeverityLevel.CRITICAL, 
                                               "CWE-78", variables):
                vulnerabilities.append(vuln)

            if vuln := self._check_vulnerability(line, i, self.xss_sinks, 
                                               "Cross-Site Scripting", SeverityLevel.HIGH, 
                                               "CWE-79", variables):
                vulnerabilities.append(vuln)

            if vuln := self._check_vulnerability(line, i, self.file_upload_sinks, 
                                               "File Upload", SeverityLevel.HIGH, 
                                               "CWE-434", variables):
                vulnerabilities.append(vuln)

            if vuln := self._check_vulnerability(line, i, self.lfi_sinks, 
                                               "Local File Inclusion", SeverityLevel.CRITICAL, 
                                               "CWE-98", variables):
                vulnerabilities.append(vuln)

            if self._is_path_traversal_vulnerable(line, file_operations):
                vuln = VulnerabilityResult(
                    type="Path Traversal",
                    severity=SeverityLevel.CRITICAL,
                    line_number=i,
                    line_content=line.strip(),
                    function="",
                    description="Path Traversal vulnerability detected: Unsanitized user input in file path operations",
                    remediation=(
                        "1. Use basename() to extract filename\n"
                        "2. Implement realpath() to resolve and validate the final path\n"
                        "3. Validate against a whitelist of allowed directories\n"
                        "4. Remove directory traversal sequences before processing\n"
                        "5. Store files outside of web root"
                    ),
                    cwe_id="CWE-22",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    owasp_category="A01:2021-Broken Access Control"
                )
                vulnerabilities.append(vuln)
            vuln = self._check_file_upload_path_traversal(line, content)
            if vuln:
                vuln.line_number = i
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _track_variables(self, lines: List[str]) -> Dict:
        variables = {}
        for i, line in enumerate(lines, 1):
            input_assign = re.search(r'\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)\[[\'"](.*?)[\'"]\]', line)
            if input_assign:
                var_name = input_assign.group(1)
                variables[var_name] = {
                    'line': i,
                    'sanitized': False,
                    'source': line.strip()
                }

            for var in variables:
                if f'${var}' in line:
                    for vuln_type, patterns in self.safe_sanitization.items():
                        for pattern in patterns:
                            if re.search(pattern + r'.*\$' + var, line):
                                variables[var][f'{vuln_type}_sanitized'] = True
                                break

        return variables

    def _track_file_operations(self, lines: List[str]) -> Dict:
        operations = {}
        for i, line in enumerate(lines, 1):
            if any(re.search(pattern, line) for pattern in self.path_traversal_sinks):
                operations[i] = {
                    'type': 'file_operation',
                    'content': line.strip(),
                    'sanitized': any(re.search(pattern, line) for pattern in self.path_traversal_sanitization),
                    'validation': []
                }
                
                if re.search(r'realpath\s*\(', line):
                    operations[i]['validation'].append('realpath')
                if re.search(r'basename\s*\(', line):
                    operations[i]['validation'].append('basename')
                if re.search(r'is_dir\s*\(|is_file\s*\(', line):
                    operations[i]['validation'].append('existence_check')
                    
        return operations

    def _is_path_traversal_vulnerable(self, line: str, operations: Dict) -> bool:
        if any(re.search(pattern, line) for pattern in self.safe_path_patterns):
            return False

        has_traversal_pattern = any(re.search(pattern, line) for pattern in self.path_traversal_sinks)
        if not has_traversal_pattern:
            return False

        has_sanitization = any(re.search(pattern, line) for pattern in self.path_traversal_sanitization)
        if has_sanitization:
            return False

        has_user_input = re.search(r'\$(?:_GET|_POST|REQUEST|_FILES)', line)
        if not has_user_input:
            return False

        return True

    def _generate_path_traversal_description(self, line: str, operations: Dict) -> str:
        description = "Path Traversal vulnerability detected: "
        
        if 'move_uploaded_file' in line:
            description += "Unsafe file upload location allows directory traversal"
        elif 'include' in line or 'require' in line:
            description += "Unsanitized file inclusion enables path traversal"
        elif any(op in line for op in ['fopen', 'file_get_contents', 'readfile']):
            description += "Unsanitized file operations enable path traversal"
        else:
            description += "Unsanitized path manipulation enables directory traversal"
            
        return description

    def _generate_path_traversal_remediation(self) -> str:
        return (
            "1. Use realpath() to resolve and validate the final path\n"
            "2. Implement basename() to extract the file name from the path\n"
            "3. Validate file paths and use realpath() to prevent directory traversal\n"
            "4. Use whitelisting and realpath() to validate file paths\n"
            "5. Implement proper input validation and sanitization"
        )

    def _check_file_upload_path_traversal(self, line: str, content: str) -> Optional[VulnerabilityResult]:
        """Specific check for path traversal in file uploads"""
        
        if not re.search(r'\$_FILES\[', line):
            return None

        if re.search(r'move_uploaded_file\s*\(', line):
            has_path_validation = any([
                re.search(pattern, content) for pattern in [
                    r'realpath\s*\(\s*\$target',
                    r'basename\s*\(\s*\$_FILES',
                    r'is_uploaded_file\s*\(\s*\$_FILES'
                ]
            ])

            has_traversal_prevention = any([
                re.search(pattern, content) for pattern in [
                    r'strpos\s*\([^,]+,\s*[\'"]\.\.[\'"]\s*\)\s*===\s*false',
                    r'str_replace\s*\(\s*[\'"]\.\.[\'"]\s*,\s*[\'"][\'"]\s*,',
                    r'preg_replace\s*\(\s*[\'"]#/\.\./#[\'"]\s*,\s*[\'"][\'"]\s*,'
                ]
            ])

            if not (has_path_validation and has_traversal_prevention):
                return VulnerabilityResult(
                    type="Path Traversal in File Upload",
                    severity=SeverityLevel.CRITICAL,
                    line_number=0,
                    line_content=line.strip(),
                    function="",
                    description=(
                        "Path Traversal vulnerability in file upload: Missing proper path validation and "
                        "directory traversal prevention. Attackers could potentially upload files to unauthorized locations."
                    ),
                    remediation=(
                        "1. Use basename() to extract filename\n"
                        "2. Implement realpath() to resolve and validate the final path\n"
                        "3. Validate file paths against a whitelist of allowed directories\n"
                        "4. Implement proper directory traversal prevention\n"
                        "5. Use is_uploaded_file() to validate upload source\n"
                        "6. Store files in a directory outside web root\n"
                        "7. Implement proper file type validation"
                    ),
                    cwe_id="CWE-22",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    owasp_category="A01:2021-Broken Access Control"
                )

        return None

class PHPVulnerabilityScanner:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.excluded_paths = set(self.config.get('excluded_paths', []))
        self.verbosity = self.config.get('verbosity', 1)
        self.max_threads = self.config.get('max_threads', 4)
        self.scan_queue = queue.Queue()
        self.results = {}
        
        self.scanners = {
            'static': StaticAnalysisScanner(),
            'dependency': DependencyScanner(),
            'config': ConfigurationScanner(),
        }

    def scan_project(self, directory: str) -> Dict[str, List[VulnerabilityResult]]:
        """Scan entire project using multiple threads."""
        print(f"Starting scan in directory: {directory}")
        php_files_found = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for root, _, files in os.walk(directory):
                if any(excluded in root for excluded in self.excluded_paths):
                    print(f"Skipping excluded directory: {root}")
                    continue
                    
                for file in files:
                    if file.endswith('.php'):
                        php_files_found += 1
                        filepath = os.path.join(root, file)
                        print(f"Queuing file for scanning: {filepath}")
                        future = executor.submit(self._scan_file, filepath)
                        futures.append(future)

            for future in futures:
                future.result()

        print(f"Total PHP files found: {php_files_found}")
        print(f"Total files with vulnerabilities: {len(self.results)}")
        return self.results

    def _scan_file(self, filepath: str):
        """Scan individual file with all available scanners."""
        try:
            print(f"\n=== Scanning file: {filepath} ===")
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
                
            file_results = []
            
            static_scanner = self.scanners['static']
            try:
                results = static_scanner.scan(content)
                if results:
                    print(f"Found {len(results)} vulnerabilities with static scanner")
                    file_results.extend(results)
                else:
                    print("No vulnerabilities found with static scanner")
            except Exception as e:
                print(f"Error in static scanner: {str(e)}")
                import traceback
                print(traceback.format_exc())
            
            for scanner_name, scanner in self.scanners.items():
                if scanner_name == 'static':
                    continue
                try:
                    print(f"\nRunning {scanner_name} scanner...")
                    results = scanner.scan(content)
                    if results:
                        print(f"Found {len(results)} vulnerabilities with {scanner_name} scanner")
                        file_results.extend(results)
                    else:
                        print(f"No vulnerabilities found with {scanner_name} scanner")
                except Exception as e:
                    print(f"Error in {scanner_name} scanner: {str(e)}")

            if file_results:
                self.results[filepath] = file_results
                print(f"Found {len(file_results)} total vulnerabilities in {filepath}")
            else:
                print("No vulnerabilities found in this file")

        except Exception as e:
            print(f"Error scanning {filepath}: {str(e)}")
            import traceback
            print(traceback.format_exc())

    def _track_variables(self, source_var: str, sink: TaintSink, variables: Dict[str, List[str]], content: str) -> List[str]:
        """Track tainted variables from source to sink"""
        tainted_vars = set([source_var])
        
        for var, assignments in variables.items():
            for assignment in assignments:
                if any(tv in assignment for tv in tainted_vars):
                    tainted_vars.add(var)
                    
                if any(f in assignment.lower() for f in ['concat', 'join', 'append', 'replace']):
                    if any(tv in assignment for tv in tainted_vars):
                        tainted_vars.add(var)
        
        sink_vars = set()
        if sink.content:
            for var in tainted_vars:
                if var in sink.content:
                    sink_vars.add(var)
                    
        return list(sink_vars)

class PHPNode:
    """Represents a node in the PHP code."""
    def __init__(self, type: str, name: str, line: int, content: str, children=None):
        self.type = type
        self.name = name
        self.line = line
        self.content = content
        self.children = children or []

    def walk(self):
        """Generator to walk through all nodes."""
        yield self
        for child in self.children:
            yield from child.walk()

class TaintFlow:
    def __init__(self, source: TaintSource, sink: TaintSink, variables: List[str]):
        self.source = source
        self.sink = sink
        self.variables = variables
        self.is_vulnerable = False
        self.simulation_results = []

class EnhancedTaintAnalyzer:
    def __init__(self):
        self.source_patterns = {
            'user_input_GET': r'\$_GET\[([\'"].*?[\'"]*)\]',
            'user_input_POST': r'\$_POST\[([\'"].*?[\'"]*)\]',
            'user_input_FILES': r'\$_FILES\[([\'"].*?[\'"]*)\]',
            'user_input_REQUEST': r'\$_REQUEST\[([\'"].*?[\'"]*)\]',
            'user_input_COOKIE': r'\$_COOKIE\[([\'"].*?[\'"]*)\]',
            'user_input_SERVER': r'\$_SERVER\[([\'"].*?[\'"]*)\]',
            'user_input_raw': r'file_get_contents\([\'"]php://input[\'"]\)',
        }
        
        self.sink_patterns = {
            'xss': r'echo|print|printf|<\?=|\$_GET|\$_POST',
            'sql': r'mysql_query|mysqli_query|PDO::query|sqlite_query|\$conn->query',
            'file': r'file_get_contents|fopen|readfile|include|require|include_once|require_once',
            'cmd': r'exec|system|shell_exec|passthru|`.*`|popen|proc_open',
            'code': r'eval|assert|create_function|unserialize',
            'xpath': r'xpath|query\s*\(',
            'ldap': r'ldap_search|ldap_bind',
            'reflection': r'ReflectionClass|ReflectionFunction|ReflectionMethod'
        }

    def _extract_variable_name(self, match_text: str) -> str:
        """Extract variable name from a regex match"""
        if match_text.startswith('$_'):
            return match_text.split('[')[1].strip('"[]')
            
        if '=' in match_text:
            return match_text.split('=')[0].strip('$ ')
            
        if '(' in match_text:
            return match_text.split('(')[1].strip('$) ')
            
        return match_text.strip('$ ')

    def _analyze_flow(self, source: TaintSource, sink: TaintSink, 
                     variables: Dict[str, List[str]], content: str) -> TaintFlow:
        """Analyze the flow between a source and sink"""
        taint_flow = TaintFlow(source, sink, [])
        source_var = self._extract_variable_name(source.match)
        
        if source_var:
            taint_flow.variables = self._track_variables(source_var, sink, variables, content)
            if self._is_vulnerable_flow(taint_flow, content):
                taint_flow.is_vulnerable = True
                
        return taint_flow

    def _track_variables(self, source_var: str, sink: TaintSink, variables: Dict[str, List[str]], content: str) -> List[str]:
        """Track variables from source to sink to detect taint flow"""
        tainted_vars = set([source_var])
        
        for var, assignments in variables.items():
            for assignment in assignments:
                if any(tv in assignment for tv in tainted_vars):
                    tainted_vars.add(var)
                    
                if any(f in assignment.lower() for f in ['concat', 'join', 'append', 'replace']):
                    if any(tv in assignment for tv in tainted_vars):
                        tainted_vars.add(var)
        
        sink_vars = set()
        if sink.content:
            for var in tainted_vars:
                if var in sink.content:
                    sink_vars.add(var)
                    
        return list(sink_vars)

    def _is_vulnerable_flow(self, taint_flow: TaintFlow, content: str) -> bool:
        """Enhanced vulnerability detection logic"""
        sanitization_functions = [
            'htmlspecialchars', 'htmlentities', 'strip_tags',
            'mysqli_real_escape_string', 'addslashes', 'escapeshellarg',
            'escapeshellcmd', 'filter_var'
        ]
        
        start_pos = taint_flow.source.line_number
        end_pos = taint_flow.sink.line_number
        code_segment = '\n'.join(content.split('\n')[start_pos-1:end_pos])
        
        for func in sanitization_functions:
            if func in code_segment:
                return False
                
        if any(var in taint_flow.sink.content for var in taint_flow.variables):
            return True
            
        return True

    def _find_sources(self, content: str) -> List[TaintSource]:
        """Find all potential taint sources in the code"""
        sources = []
        for source_type, pattern in self.source_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content.count('\n', 0, match.start()) + 1
                sources.append(TaintSource(
                    source_type=source_type,
                    match=match.group(0),
                    line_number=line_number,
                    content=content[match.start():match.end()]
                ))
        return sources

    def _find_sinks(self, content: str) -> List[TaintSink]:
        """Find all potential taint sinks in the code"""
        sinks = []
        for sink_type, pattern in self.sink_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content.count('\n', 0, match.start()) + 1
                sinks.append(TaintSink(
                    sink_type=sink_type,
                    match=match.group(0),
                    line_number=line_number,
                    content=content[match.start():match.end()]
                ))
        return sinks

    def analyze(self, content: str) -> List[VulnerabilityResult]:
        """Enhanced analysis with better vulnerability detection"""
        vulnerabilities = []
        sources = self._find_sources(content)
        sinks = self._find_sinks(content)
        variables = self._track_all_variables(content)
        
        for source in sources:
            for sink in sinks:
                tainted_vars = self._track_variables(
                    source_var=self._extract_variable_name(source.match),
                    sink=sink,
                    variables=variables,
                    content=content
                )
                
                if tainted_vars:
                    taint_flow = TaintFlow(source, sink, tainted_vars)
                    if self._is_vulnerable_flow(taint_flow, content):
                        severity = self._determine_severity(source, sink)
                        vuln = VulnerabilityResult(
                            type=f"{sink.sink_type}_vulnerability",
                            severity=severity,
                            line_number=sink.line_number,
                            line_content=sink.content,
                            function=self._get_function_context(content, sink.line_number),
                            description=self._generate_description(source, sink),
                            remediation=self._generate_remediation(sink.sink_type),
                            cwe_id=self._get_cwe_id(sink.sink_type),
                            references=self._get_references(sink.sink_type),
                            owasp_category=self._get_owasp_category(sink.sink_type)
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _determine_severity(self, source: TaintSource, sink: TaintSink) -> SeverityLevel:
        """Determine vulnerability severity based on source and sink types"""
        critical_sinks = ['cmd', 'code']
        high_sinks = ['sql', 'xpath', 'ldap']
        medium_sinks = ['xss', 'file']
        
        if sink.sink_type in critical_sinks:
            return SeverityLevel.CRITICAL
        elif sink.sink_type in high_sinks:
            return SeverityLevel.HIGH
        elif sink.sink_type in medium_sinks:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _generate_description(self, source: TaintSource, sink: TaintSink) -> str:
        """Generate detailed vulnerability description"""
        return f"Unsanitized data from {source.source_type} ({source.match}) " \
               f"flows into {sink.sink_type} sink ({sink.match}) at line {sink.line_number}"

    def _generate_remediation(self, sink_type: str) -> str:
        """Generate specific remediation advice"""
        remediation_advice = {
            'xss': "Use htmlspecialchars() or htmlentities() to encode output",
            'sql': "Use prepared statements or mysqli_real_escape_string()",
            'cmd': "Use escapeshellarg() or escapeshellcmd() for command arguments",
            'file': "Validate file paths and use basename() to prevent directory traversal",
            'code': "Avoid using eval() or other dynamic code execution functions",
        }
        return remediation_advice.get(sink_type, "Implement proper input validation and sanitization")

    def _track_all_variables(self, content: str) -> Dict[str, List[str]]:
        """Track all variable assignments in the code"""
        variables = {}
        
        assignment_pattern = r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*([^;]+)'
        matches = re.finditer(assignment_pattern, content)
        
        for match in matches:
            var_name = match.group(1)
            assignment = match.group(2)
            
            if var_name not in variables:
                variables[var_name] = []
            variables[var_name].append(assignment.strip())
        
        return variables

class PHPParser:
    """Simple PHP parser using regex patterns."""
    
    def __init__(self):
        self.patterns = {
            'function_call': r'(\w+)\s*\((.*?)\)',
            'variable': r'\$\w+',
            'class': r'class\s+(\w+)',
            'method': r'function\s+(\w+)\s*\((.*?)\)',
        }

    def parse(self, content: str):
        """
        Parse PHP content into a simple AST-like structure.
        
        Args:
            content: PHP code as string
            
        Returns:
            PHPNode: Root node of the parsed structure
        """
        lines = content.split('\n')
        root = PHPNode('root', 'root', 0, content)
        children = []

        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(self.patterns['function_call'], line):
                func_name = match.group(1)
                children.append(PHPNode(
                    type='function_call',
                    name=func_name,
                    line=line_num,
                    content=line.strip()
                ))

            for match in re.finditer(self.patterns['variable'], line):
                children.append(PHPNode(
                    type='variable',
                    name=match.group(0),
                    line=line_num,
                    content=line.strip()
                ))

            for match in re.finditer(self.patterns['class'], line):
                children.append(PHPNode(
                    type='class',
                    name=match.group(1),
                    line=line_num,
                    content=match.group(0)
                ))

            for match in re.finditer(self.patterns['method'], line):
                children.append(PHPNode(
                    type='method',
                    name=match.group(1),
                    line=line_num,
                    content=match.group(0)
                ))

        root.children = children
        return root

    def _extract_params(self, param_str: str) -> List[str]:
        """Extract parameters from a parameter string."""
        return [p.strip() for p in param_str.split(',') if p.strip()]

class DependencyScanner(VulnerabilityScanner):
    """Advanced dependency analysis."""
    
    def __init__(self):
        self.advisories_api = SecurityAdvisoriesAPI()
        
    def scan(self, content: str) -> List[VulnerabilityResult]:
        results = []
        
        if 'composer.json' in content or 'composer.lock' in content:
            dependencies = self._parse_dependencies(content)
            
            for dep in dependencies:
                vulnerabilities = self.advisories_api.check_package(dep)
                results.extend(self._convert_to_results(vulnerabilities))
                
        return results

class ConfigurationScanner(VulnerabilityScanner):
    """Configuration and environment analysis."""
    
    def __init__(self):
        self.dangerous_settings = {
            'display_errors': 'On',
            'allow_url_include': 'On',
            'expose_php': 'On',
            'session.use_strict_mode': 'Off',
        }
        
    def _check_php_config(self, content: str) -> List[VulnerabilityResult]:
        """Check for dangerous PHP configuration settings."""
        results = []
        
        for setting, dangerous_value in self.dangerous_settings.items():
            pattern = rf'ini_set\([\'"]?{setting}[\'"]?,\s*[\'"]?{dangerous_value}[\'"]?\)'
            matches = re.finditer(pattern, content)
            
            for match in matches:
                results.append(VulnerabilityResult(
                    type='Dangerous Configuration',
                    severity=SeverityLevel.HIGH,
                    line_number=content.count('\n', 0, match.start()) + 1,
                    line_content=match.group(),
                    function='N/A',
                    description=f'Dangerous PHP configuration: {setting} = {dangerous_value}',
                    remediation=f'Remove or secure the {setting} configuration',
                    cwe_id='CWE-756',
                    references=['https://www.php.net/manual/en/security.php']
                ))
                
        return results

    def scan(self, content: str) -> List[VulnerabilityResult]:
        """Scan for configuration vulnerabilities."""
        results = []
        results.extend(self._check_php_config(content))
        return results

class ReportGenerator:
    """Generate detailed vulnerability reports."""
    
    def __init__(self, results: Dict[str, List[VulnerabilityResult]]):
        self.results = results
        
    def generate_html(self, output_file: str):
        """Generate enhanced HTML report with visualizations."""
        print(f"\nGenerating HTML report to: {output_file}")
        print(f"Number of files with vulnerabilities: {len(self.results)}")

        total_vulns = sum(len(vulns) for vulns in self.results.values())
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        vulnerability_content = ""
        for filepath, vulnerabilities in self.results.items():
            if vulnerabilities:
                print(f"\nProcessing file: {filepath}")
                print(f"Number of vulnerabilities: {len(vulnerabilities)}")
                
                vulnerability_content += f'<h2>{html.escape(filepath)}</h2><div class="vulnerability-list">'
                
                for vuln in vulnerabilities:
                    severity_counts[vuln.severity.name] += 1
                    print(f"- {vuln.type} ({vuln.severity.name}) on line {vuln.line_number}")
                    
                    vulnerability_content += f"""
                        <div class="vulnerability-card severity-{vuln.severity.name}">
                            <div class="vuln-header">
                                <span class="vuln-type">{html.escape(vuln.type)}</span>
                                <span class="severity-badge {vuln.severity.name}">{vuln.severity.name}</span>
                            </div>
                            <div class="line-info">
                                <div class="line-number">Line {vuln.line_number}</div>
                                <div class="line-content">
                                    {html.escape(vuln.line_content)}
                                    <button class="copy-button" onclick="copyToClipboard(`{html.escape(vuln.line_content)}`)">Copy</button>
                                </div>
                            </div>
                            <div class="vuln-details">
                                <div class="detail-item">
                                    <span class="detail-label">Description:</span>
                                    <p>{html.escape(vuln.description)}</p>
                                </div>
                                <div class="remediation">
                                    <span class="detail-label">Remediation:</span>
                                    <p>{html.escape(vuln.remediation)}</p>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">CWE:</span>
                                    <span>{html.escape(vuln.cwe_id)}</span>
                                </div>
                            </div>
                        </div>
                    """
                vulnerability_content += '</div>'

        html_content = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Security Vulnerability Report</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                :root {{
                    --critical-color: #dc3545;
                    --high-color: #fd7e14;
                    --medium-color: #ffc107;
                    --low-color: #0dcaf0;
                    --info-color: #20c997;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                    color: #212529;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 2rem;
                }}
                
                header {{
                    text-align: center;
                    margin-bottom: 3rem;
                    padding: 2rem;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                
                header h1 {{
                    margin: 0;
                    color: #2c3e50;
                    font-size: 2.5rem;
                }}
                
                header p {{
                    color: #6c757d;
                    margin: 0.5rem 0 0;
                }}
                
                .summary-cards {{
                    display: flex;
                    justify-content: center;
                    margin-bottom: 3rem;
                }}
                
                .summary-card {{
                    background: white;
                    padding: 1.5rem;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                    min-width: 200px;
                }}
                
                .summary-card h3 {{
                    margin: 0;
                    color: var(--critical-color);
                    font-size: 1.2rem;
                }}
                
                .count {{
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: var(--critical-color);
                    margin: 0.5rem 0;
                }}
                
                .vulnerability-list {{
                    display: grid;
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }}
                
                .vulnerability-card {{
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                
                .vuln-header {{
                    padding: 1rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    background: #f8f9fa;
                    border-bottom: 1px solid #e9ecef;
                }}
                
                .vuln-type {{
                    font-weight: bold;
                    color: #2c3e50;
                }}
                
                .severity-badge {{
                    padding: 0.25rem 0.75rem;
                    border-radius: 20px;
                    font-size: 0.875rem;
                    font-weight: 500;
                    color: white;
                }}
                
                .severity-badge.CRITICAL {{ background-color: var(--critical-color); }}
                .severity-badge.HIGH {{ background-color: var(--high-color); }}
                .severity-badge.MEDIUM {{ background-color: var(--medium-color); }}
                .severity-badge.LOW {{ background-color: var(--low-color); }}
                .severity-badge.INFO {{ background-color: var(--info-color); }}
                
                .line-info {{
                    padding: 1rem;
                    background: #f8f9fa;
                    border-bottom: 1px solid #e9ecef;
                }}
                
                .line-number {{
                    font-family: monospace;
                    color: #6c757d;
                    margin-bottom: 0.5rem;
                }}
                
                .line-content {{
                    background: #2c3e50;
                    color: #f8f9fa;
                    padding: 1rem;
                    border-radius: 5px;
                    font-family: monospace;
                    position: relative;
                    overflow-x: auto;
                }}
                
                .copy-button {{
                    position: absolute;
                    right: 0.5rem;
                    top: 0.5rem;
                    background: rgba(255,255,255,0.1);
                    border: none;
                    color: white;
                    padding: 0.25rem 0.5rem;
                    border-radius: 3px;
                    cursor: pointer;
                    font-size: 0.875rem;
                }}
                
                .copy-button:hover {{
                    background: rgba(255,255,255,0.2);
                }}
                
                .vuln-details {{
                    padding: 1rem;
                }}
                
                .detail-item {{
                    margin-bottom: 1rem;
                }}
                
                .detail-label {{
                    font-weight: 600;
                    color: #2c3e50;
                    display: block;
                    margin-bottom: 0.25rem;
                }}
                
                h2 {{
                    color: #2c3e50;
                    margin: 2rem 0 1rem;
                    padding-bottom: 0.5rem;
                    border-bottom: 2px solid #e9ecef;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Security Vulnerability Report</h1>
                    <p>Generated on: {datetime.datetime.now().strftime("%B %d, %Y at %I:%M:%S %p")}</p>
                </header>

                <div class="summary-cards">
                    <div class="summary-card">
                        <h3>Critical Issues</h3>
                        <div class="count">{severity_counts['CRITICAL']}</div>
                    </div>
                </div>

                <div id="vulnerability-results">
                    {vulnerability_content}
                </div>
            </div>

            <script>
                function copyToClipboard(text) {{
                    navigator.clipboard.writeText(text).then(() => {{
                        const notification = document.createElement('div');
                        notification.textContent = 'Copied to clipboard!';
                        notification.style.cssText = `
                            position: fixed;
                            bottom: 20px;
                            right: 20px;
                            background: #28a745;
                            color: white;
                            padding: 1rem;
                            border-radius: 5px;
                            animation: fadeOut 2s forwards;
                            z-index: 1000;
                        `;
                        document.body.appendChild(notification);
                        setTimeout(() => notification.remove(), 2000);
                    }}).catch(err => console.error('Failed to copy text: ', err));
                }}
            </script>
        </body>
        </html>
        """

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"\nReport generated successfully: {output_file}")
        print(f"Total vulnerabilities included: {total_vulns}")

    def generate_json(self, output_file: str):
        """Generate JSON report for CI/CD integration."""
        report = {
            'scan_results': {
                filepath: [
                    {
                        'type': vuln.type,
                        'severity': vuln.severity.name,
                        'line_number': vuln.line_number,
                        'line_content': vuln.line_content,
                        'description': vuln.description,
                        'remediation': vuln.remediation,
                        'cwe_id': vuln.cwe_id
                    }
                    for vuln in vulnerabilities
                ]
                for filepath, vulnerabilities in self.results.items()
                if vulnerabilities
            }
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
    def generate_xml(self, output_file: str):
        """Generate XML report for CI/CD integration."""
        root = ET.Element("vulnerability_report")
        
        for filepath, vulnerabilities in self.results.items():
            if vulnerabilities:
                file_elem = ET.SubElement(root, "file")
                file_elem.set("path", filepath)
                
                for vuln in vulnerabilities:
                    vuln_elem = ET.SubElement(file_elem, "vulnerability")
                    ET.SubElement(vuln_elem, "type").text = vuln.type
                    ET.SubElement(vuln_elem, "severity").text = vuln.severity.name
                    ET.SubElement(vuln_elem, "line_number").text = str(vuln.line_number)
                    ET.SubElement(vuln_elem, "line_content").text = vuln.line_content
                    ET.SubElement(vuln_elem, "description").text = vuln.description
                    ET.SubElement(vuln_elem, "remediation").text = vuln.remediation
                    ET.SubElement(vuln_elem, "cwe_id").text = vuln.cwe_id
        
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)

class SecurityAdvisoriesAPI:
    """API client for checking security advisories."""
    
    def __init__(self):
        self.api_url = "https://packagist.security-advisories.com/api"
        
    def check_package(self, dependency: dict) -> List[dict]:
        """
        Check a package against known security advisories.
        
        Args:
            dependency: Dictionary containing package name and version
        
        Returns:
            List of vulnerability dictionaries
        """
        return []

class DebugLogger:
    def __init__(self, output_dir: str = "debug_logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.debug_file = self.output_dir / f"debug_log_{timestamp}.txt"
        self.original_stdout = sys.stdout
        self.debug_file_handle = open(self.debug_file, 'w', encoding='utf-8')
        
        sys.stdout = self

    def write(self, text):
        """Write to both console and debug file"""
        self.original_stdout.write(text)
        self.debug_file_handle.write(text)
        self.debug_file_handle.flush()

    def flush(self):
        """Flush both outputs"""
        self.original_stdout.flush()
        self.debug_file_handle.flush()

    def __del__(self):
        """Cleanup when object is destroyed"""
        sys.stdout = self.original_stdout
        if hasattr(self, 'debug_file_handle'):
            self.debug_file_handle.close()

def print_banner():
    banner = f"""{Fore.CYAN}
           < PHP Static Analysis Security Scanner >
              ~( Tickle Your PHP Security )~

              Coded with ❤️   by Aymen @J4k0m
                     Version: 1.0.0
    {Style.RESET_ALL}"""
    print(banner)

def main():
    """Main function with enhanced CLI options."""
    init()
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='PHPTickler - PHP Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--directory', required=True,
                      help='Directory to scan')
    parser.add_argument('--exclude', nargs='+',
                      help='Paths to exclude from scanning')
    parser.add_argument('--threads', type=int, default=4,
                      help='Number of scanning threads')
    parser.add_argument('--format', choices=['html', 'json', 'xml'],
                      default='html', help='Report format')
    parser.add_argument('-v', '--verbosity', type=int, choices=[0, 1, 2],
                      default=1, help='Verbosity level')
    
    args = parser.parse_args()
    
    config = {
        'excluded_paths': args.exclude or [],
        'verbosity': args.verbosity,
        'max_threads': args.threads
    }
    
    print(f"{Fore.CYAN}Starting scan of directory: {args.directory}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Initializing scanner...{Style.RESET_ALL}")
    
    scanner = PHPVulnerabilityScanner(config)
    
    print(f"{Fore.CYAN}Scanning files...{Style.RESET_ALL}")
    results = scanner.scan_project(args.directory)
    
    if not results:
        print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.YELLOW}Scan Results:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}-------------{Style.RESET_ALL}")
    
    total_vulnerabilities = 0
    severity_colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.LIGHTRED_EX,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.BLUE,
        'INFO': Fore.GREEN
    }
    
    for filepath, vulnerabilities in results.items():
        if vulnerabilities:
            print(f"\n{Fore.CYAN}File: {filepath}{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                total_vulnerabilities += 1
                severity_color = severity_colors.get(vuln.severity.name, '')
                print(f"\n  {severity_color}- Type: {vuln.type}")
                print(f"    Severity: {vuln.severity.name}")
                print(f"    Line {vuln.line_number}: {vuln.line_content}")
                print(f"    Description: {vuln.description}")
                print(f"    Remediation: {vuln.remediation}")
                print(f"    CWE: {vuln.cwe_id}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Total vulnerabilities found: {total_vulnerabilities}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Generating {args.format} report...{Style.RESET_ALL}")
    report_generator = ReportGenerator(results)
    report_path = f'vulnerability_report.{args.format}'
    
    if args.format == 'html':
        report_generator.generate_html(report_path)
    elif args.format == 'json':
        report_generator.generate_json(report_path)
    else:
        report_generator.generate_xml(report_path)
    
    print(f"Report generated: {report_path}")

if __name__ == "__main__":
    main()
