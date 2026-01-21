#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP SECURITY MONITOR v4.0 - CYBERSECURITY EXPERT EDITION
Multi-level threat detection with AI-inspired heuristics
"""

import os
import sys
import re
import time
import hashlib
import subprocess
import configparser
import urllib.parse
import json
import logging
import mmap
import magic
import gc
import traceback
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any, Callable
from collections import defaultdict, Counter
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

# ====================================================================
# ENHANCED CONFIGURATION WITH DETECTION LEVELS
# ====================================================================

@dataclass
class DetectionRule:
    """Rule for threat detection"""
    name: str
    pattern: str
    severity: str  # low, medium, high, critical
    description: str
    confidence: float  # 0.0 to 1.0
    regex: Optional[re.Pattern] = None
    tags: List[str] = None
    
    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        if self.tags is None:
            self.tags = []


class ThreatIntelligence:
    """Threat intelligence feed and heuristics"""
    
    # Known malware signatures (partial list for demonstration)
    MALWARE_SIGNATURES = {
        "WebShell": [
            (r'@\$_=\$_(GET|POST|REQUEST)\[', "WebShell parameter access"),
            (r'preg_replace.*/e.*@.*\$_', "preg_replace /e webshell"),
            (r'@ini_set.*error_log.*0', "Error suppression webshell"),
            (r'passthru.*base64_decode', "Command execution webshell"),
        ],
        "Backdoor": [
            (r'/\*\s*backdoor\s*\*/.*?\*/', "Comment backdoor"),
            (r'if.*isset.*\$_GET\[\'c\'\]', "Simple command backdoor"),
            (r'file_put_contents.*\$_POST', "File upload backdoor"),
        ],
        "Obfuscation": [
            (r'eval.*gzuncompress.*base64_decode', "Double obfuscation"),
            (r'str_rot13.*base64_decode', "ROT13+Base64 obfuscation"),
            (r'preg_replace.*\$\w+\s*\(', "Dynamic function call"),
        ]
    }
    
    # Entropy thresholds for obfuscation detection
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        counter = Counter(data)
        entropy = 0.0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * (p and math.log(p, 2))
        return entropy
    
    @staticmethod
    def is_high_entropy(text: str, threshold: float = 4.5) -> bool:
        """Detect high entropy (potential obfuscation)"""
        return ThreatIntelligence.calculate_entropy(text) > threshold


class EnhancedConfig:
    """Enhanced configuration with detection levels"""
    
    DETECTION_LEVELS = {
        "simple": {
            "check_permissions": True,
            "check_recent_files": True,
            "check_suspicious_code": True,
            "use_whitelist": False,
            "max_file_size": 5242880,  # 5MB
            "entropy_threshold": 5.0,
            "enable_heuristics": False,
        },
        "advanced": {
            "check_permissions": True,
            "check_recent_files": True,
            "check_suspicious_code": True,
            "use_whitelist": True,
            "max_file_size": 10485760,  # 10MB
            "entropy_threshold": 4.5,
            "enable_heuristics": True,
            "check_code_patterns": True,
            "check_entropy": True,
            "check_malware_signatures": True,
            "check_obfuscation": True,
            "check_dynamic_execution": True,
            "check_database_content": False,  # Security first
        }
    }
    
    def __init__(self, detection_level: str = "advanced"):
        self.detection_level = detection_level
        self.config_file = Path("/etc/php_monitor_v4.conf")
        self.log_dir = Path("/var/log/php_monitor_v4")
        self.snapshot_dir = Path("/var/lib/php_monitor_v4/snapshots")
        self.baseline_file = Path("/var/lib/php_monitor_v4/baseline.json")
        self.threat_db_file = Path("/var/lib/php_monitor_v4/threats.json")
        
        # Load detection level settings
        self.settings = self.DETECTION_LEVELS.get(detection_level, self.DETECTION_LEVELS["advanced"])
        
        # Web paths
        self.web_root = "/var/www/html"
        self.php_paths = ["/var/www/html"]
        self.sensitive_dirs = ["uploads", "tmp", "cache", "temp", "images", "media"]
        
        # Log paths
        self.log_paths = ["/var/log/apache2", "/var/log/nginx"]
        self.ftp_log = "/var/log/vsftpd.log"
        
        # Parameters
        self.recent_hours = 24
        self.max_file_size = self.settings["max_file_size"]
        self.db_check_enabled = self.settings.get("check_database_content", False)
        
        # Whitelist patterns (only used in advanced mode)
        self.whitelist_patterns = [
            r'//\s*@ignore-security-scan',
            r'/\*\s*security-scan-ignore\s*\*/',
            r'Framework::',
            r'WordPress.*wp-content',
            r'Joomla!.*component',
            r'Drupal.*sites/all',
        ]
        
        # Load configuration if exists
        self.load_config()
        
        # Initialize detection rules based on level
        self.init_detection_rules()
        
    def init_detection_rules(self):
        """Initialize detection rules based on detection level"""
        
        # BASE RULES (for both levels)
        self.base_rules = [
            # Critical: Direct code execution
            DetectionRule(
                name="EVAL_EXECUTION",
                pattern=r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[',
                severity="critical",
                description="Direct eval on user input",
                confidence=0.95,
                tags=["code-execution", "webshell"]
            ),
            
            # Critical: System command execution
            DetectionRule(
                name="SYSTEM_EXECUTION",
                pattern=r'(system|shell_exec|exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[',
                severity="critical",
                description="System command execution from user input",
                confidence=0.90,
                tags=["code-execution", "rce"]
            ),

            DetectionRule(
                name="DANGEROUS_PHP_WRAPPER",
                pattern=r'php://(input|filter|memory|temp)',
                severity="critical",
                description="Potential PHP wrapper exploitation",
                confidence=0.95,
                tags=["rce", "lfi"]
            ),

            DetectionRule(
                name="HIDDEN_WEBSHELL",
                pattern=r'@eval\(|assert\(|create_function',
                severity="critical",
                description="Hidden backdoor pattern",
                confidence=0.98,
                tags=["webshell"]
            ),

            DetectionRule(
                name="MALICIOUS_UPLOAD",
                pattern=r'move_uploaded_file.*\$_FILES',
                severity="high",
                description="Potential malicious file upload",
                confidence=0.85,
                tags=["backdoor"]
            ),



            # High: File manipulation
            DetectionRule(
                name="FILE_MANIPULATION",
                pattern=r'(file_put_contents|fwrite|fopen|unlink)\s*\(\s*\$_(GET|POST|REQUEST)\[',
                severity="high",
                description="File manipulation from user input",
                confidence=0.85,
                tags=["file-write", "backdoor"]
            ),
            
            # High: Database manipulation
            DetectionRule(
                name="DB_MANIPULATION",
                pattern=r'mysql_query|mysqli_query|PDO::query.*\$_(GET|POST|REQUEST)\[',
                severity="high",
                description="Database query from user input without sanitization",
                confidence=0.80,
                tags=["sql-injection", "db-manipulation"]
            ),
        ]
        
        # SIMPLE MODE RULES (broad detection)
        self.simple_rules = self.base_rules + [
            # Medium: Obfuscation techniques
            DetectionRule(
                name="OBFUSCATION_BASE64",
                pattern=r'base64_decode\s*\([^)]*\)',
                severity="medium",
                description="Base64 decode usage",
                confidence=0.60,
                tags=["obfuscation", "encoding"]
            ),
            
            # Medium: Dynamic code execution
            DetectionRule(
                name="DYNAMIC_EXECUTION",
                pattern=r'\$\w+\s*\(\s*\$',
                severity="medium",
                description="Dynamic function/variable execution",
                confidence=0.65,
                tags=["dynamic-code", "obfuscation"]
            ),
            
            # Low: Suspicious includes
            DetectionRule(
                name="SUSPICIOUS_INCLUDE",
                pattern=r'(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)\[',
                severity="low",
                description="Dynamic file inclusion from user input",
                confidence=0.70,
                tags=["lfi", "file-inclusion"]
            ),
        ]
        
        # ADVANCED MODE RULES (precise detection with context)
        self.advanced_rules = self.base_rules + [
            # Critical: Advanced obfuscation chains
            DetectionRule(
                name="ADV_OBFUSCATION_CHAIN",
                pattern=r'eval\s*\(\s*(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode',
                severity="critical",
                description="Multi-layer obfuscation chain",
                confidence=0.98,
                tags=["obfuscation", "webshell", "advanced"]
            ),
            
            # High: Serialized PHP objects (potential PHP object injection)
            DetectionRule(
                name="PHP_OBJECT_INJECTION",
                pattern=r'unserialize\s*\(\s*\$_(GET|POST|REQUEST)\[',
                severity="high",
                description="PHP object injection vulnerability",
                confidence=0.85,
                tags=["deserialization", "rce", "advanced"]
            ),
            
            # High: Reflection for code execution
            DetectionRule(
                name="REFLECTION_EXECUTION",
                pattern=r'ReflectionFunction|create_function.*\$_(GET|POST)',
                severity="high",
                description="Reflection-based code execution",
                confidence=0.80,
                tags=["reflection", "code-execution", "advanced"]
            ),
            
            # Medium: XOR obfuscation
            DetectionRule(
                name="XOR_OBFUSCATION",
                pattern=r'\^.*\^.*\^.*base64_decode|pack\s*\(\s*[\'"]H*[\'"]',
                severity="medium",
                description="XOR or pack-based obfuscation",
                confidence=0.75,
                tags=["obfuscation", "encoding", "advanced"]
            ),
            
            # Medium: JavaScript injection in PHP
            DetectionRule(
                name="JS_IN_PHP_INJECTION",
                pattern=r'echo\s*[\'"]<script>.*eval.*</script>[\'"]',
                severity="medium",
                description="JavaScript injection within PHP",
                confidence=0.70,
                tags=["xss", "injection", "advanced"]
            ),
        ]
        
        # Select rules based on detection level
        if self.detection_level == "simple":
            self.rules = self.simple_rules
        else:
            self.rules = self.advanced_rules
            
        # Compile whitelist regex
        self.whitelist_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.whitelist_patterns
        ] if self.settings.get("use_whitelist", False) else []
        
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                config = configparser.ConfigParser()
                config.read(self.config_file)
                
                if 'PHP_MONITOR' in config:
                    section = config['PHP_MONITOR']
                    
                    # Load lists as JSON
                    list_fields = ['php_paths', 'log_paths', 'sensitive_dirs']
                    for field in list_fields:
                        if field in section:
                            setattr(self, field, json.loads(section[field]))
                    
                    # Load simple values
                    if 'detection_level' in section:
                        self.detection_level = section['detection_level']
                        self.settings = self.DETECTION_LEVELS.get(
                            self.detection_level, 
                            self.DETECTION_LEVELS["advanced"]
                        )
                    
                    # Update settings from config
                    for key in ['recent_hours', 'max_file_size']:
                        if key in section:
                            setattr(self, key, int(section[key]))
                            
            except Exception as e:
                print(f"Warning: Error loading config: {e}")


# ====================================================================
# BASELINE MANAGEMENT
# ====================================================================

class FileBaselineManager:
    """Gestion de la baseline (empreintes des fichiers)"""

    def __init__(self, config: EnhancedConfig):
        self.config = config
        self.baseline_file = config.baseline_file

    def compute_file_hash(self, filepath: str) -> str:
        """Calcule le hash SHA256 du fichier"""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def create_baseline(self, paths: List[str]) -> Dict[str, str]:
        """Cree une baseline des fichiers PHP"""
        print("\n[+] Création de la baseline des fichiers...")

        baseline = {}

        for path in paths:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not any(x in os.path.join(root, d) for x in [
                    "/vendor/", "/node_modules/", "/.git/", "/cache/", "/tmp/"
                ])]

                for file in files:
                    if file.endswith((".php", ".phtml", ".php5", ".php7")):
                        filepath = os.path.join(root, file)
                        try:
                            baseline[filepath] = self.compute_file_hash(filepath)
                        except Exception as e:
                            print(f"[-] Erreur hash {filepath}: {e}")

        with open(self.baseline_file, "w") as f:
            json.dump(baseline, f, indent=2)

        print(f"[+] Baseline créée : {self.baseline_file}")
        return baseline

    def load_baseline(self) -> Dict[str, str]:
        if not self.baseline_file.exists():
            print("[-] Aucune baseline trouvée !")
            return {}

        with open(self.baseline_file, "r") as f:
            return json.load(f)

    def compare_with_baseline(self, current_paths: List[str]) -> Dict[str, List[str]]:
        """Compare l’état actuel avec la baseline"""
        print("\n[+] Comparaison avec la baseline...")

        baseline = self.load_baseline()
        current_files = {}
        modified = []
        deleted = []
        new_files = []

        # Scanner les fichiers actuels
        for path in current_paths:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not any(x in os.path.join(root, d) for x in [
                    "/vendor/", "/node_modules/", "/.git/", "/cache/", "/tmp/"
                ])]

                for file in files:
                    if file.endswith(".php"):
                        filepath = os.path.join(root, file)
                        try:
                            current_files[filepath] = self.compute_file_hash(filepath)
                        except:
                            pass

        # Détection des fichiers modifiés
        for file, hash_val in current_files.items():
            if file in baseline:
                if baseline[file] != hash_val:
                    modified.append(file)
            else:
                new_files.append(file)

        # Détection des fichiers supprimés
        for file in baseline:
            if file not in current_files:
                deleted.append(file)

        return {
            "modified": modified,
            "deleted": deleted,
            "new": new_files
        }


# ====================================================================
# ENHANCED LOGGING WITH THREAT SCORING
# ====================================================================

class ThreatLogger:
    """Advanced logging with threat scoring and categorization"""
    
    def __init__(self, config: EnhancedConfig):
        self.config = config
        self.log_dir = config.log_dir
        self.setup_logging()
        
        # Threat tracking
        self.threats_by_severity = defaultdict(list)
        self.threat_scores = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        self.total_threat_score = 0
        
    def setup_logging(self):
        """Setup multi-level logging system"""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"scan_{timestamp}.log"
        self.alert_file = self.log_dir / f"alerts_{timestamp}.log"
        self.report_file = self.log_dir / f"report_{timestamp}.txt"
        self.threat_file = self.log_dir / f"threats_{timestamp}.json"
        
        # Main logger
        self.logger = logging.getLogger('php_monitor_v4')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        
        # File handler (all logs)
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        
        # Console handler (important logs only)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'
        ))
        self.logger.addHandler(console_handler)
        
        # Alert handler (WARNING and above)
        alert_handler = logging.FileHandler(self.alert_file)
        alert_handler.setLevel(logging.WARNING)
        alert_handler.setFormatter(logging.Formatter(
            '%(asctime)s - [%(levelname)s] %(message)s'
        ))
        self.logger.addHandler(alert_handler)
        
    def log_threat(self, rule: DetectionRule, filepath: str, 
                   line_num: int = None, line_content: str = None,
                   context: Dict = None):
        """Log a threat with detailed information"""
        
        threat_entry = {
            "timestamp": datetime.now().isoformat(),
            "rule": rule.name,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "description": rule.description,
            "file": filepath,
            "line": line_num,
            "tags": rule.tags,
            "context": context or {}
        }
        
        if line_content:
            threat_entry["content"] = line_content[:200]
        
        # Add to severity tracking
        self.threats_by_severity[rule.severity].append(threat_entry)
        
        # Calculate threat score
        score = self.threat_scores.get(rule.severity, 1)
        self.total_threat_score += score
        
        # Log message
        location = f"line {line_num}" if line_num else filepath
        msg = (f"[{rule.severity.upper()}] {rule.name}: {rule.description} "
               f"in {filepath} ({location})")
        
        if rule.severity in ["critical", "high"]:
            self.logger.error(msg)
            if line_content:
                self.logger.error(f"  Content: {line_content[:100]}")
        else:
            self.logger.warning(msg)
        
        # Save to threat file
        self.save_threat(threat_entry)
        
        # Add to report
        with open(self.report_file, 'a', encoding='utf-8') as f:
            f.write(f"[{rule.severity.upper()}] {rule.name} - {filepath}\n")
            if line_num:
                f.write(f"  Line {line_num}: {line_content[:100] if line_content else ''}\n")
        
        return threat_entry
    
    def save_threat(self, threat: Dict):
        """Save threat to JSON file"""
        try:
            threats = []
            if self.threat_file.exists():
                with open(self.threat_file, 'r') as f:
                    threats = json.load(f)
            
            threats.append(threat)
            
            with open(self.threat_file, 'w') as f:
                json.dump(threats, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save threat: {e}")
    
    def get_summary(self) -> Dict:
        """Get threat summary"""
        return {
            "total_threats": sum(len(v) for v in self.threats_by_severity.values()),
            "threats_by_severity": dict(self.threats_by_severity),
            "total_threat_score": self.total_threat_score,
            "detection_level": self.config.detection_level,
            "scan_time": datetime.now().isoformat()
        }
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "="*70)
        print("THREAT DETECTION SUMMARY")
        print("="*70)
        
        summary = self.get_summary()
        
        print(f"\nDetection Level: {self.config.detection_level.upper()}")
        print(f"Total Threat Score: {summary['total_threat_score']}")
        
        for severity in ["critical", "high", "medium", "low"]:
            count = len(self.threats_by_severity.get(severity, []))
            if count > 0:
                print(f"\n{severity.upper()} threats: {count}")
                for i, threat in enumerate(self.threats_by_severity[severity][:5], 1):
                    print(f"  {i}. {threat['rule']} - {threat['file']}")
                if count > 5:
                    print(f"  ... and {count - 5} more")
        
        print(f"\nDetailed reports:")
        print(f"  Full log: {self.log_file}")
        print(f"  Alerts: {self.alert_file}")
        print(f"  Threats (JSON): {self.threat_file}")
        print("="*70)


# ====================================================================
# ENHANCED FILE SCANNER WITH MULTI-LEVEL DETECTION
# ====================================================================

class EnhancedFileScanner:
    """Advanced file scanner with heuristic detection"""
    
    def __init__(self, config: EnhancedConfig, logger: ThreatLogger):
        self.config = config
        self.logger = logger
        self.threat_intel = ThreatIntelligence()
        
        # File type detection
        self.mime = magic.Magic(mime=True)
        
        # Statistics
        self.stats = {
            "files_scanned": 0,
            "files_with_threats": 0,
            "rules_triggered": defaultdict(int),
            "execution_time": 0
        }
        
    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single file for threats"""
        threats = []
        
        try:
            # Skip if too large
            if os.path.getsize(filepath) > self.config.max_file_size:
                return threats
            
            # Read file content
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.stats["files_scanned"] += 1
            
            # Check whitelist (only in advanced mode)
            if self.config.settings.get("use_whitelist", False):
                if self.is_whitelisted(content):
                    return threats
            
            # Apply detection rules
            file_threats = self.apply_detection_rules(filepath, content)
            threats.extend(file_threats)
            
            # Advanced heuristics (only in advanced mode)
            if self.config.settings.get("enable_heuristics", False):
                heuristic_threats = self.apply_heuristics(filepath, content)
                threats.extend(heuristic_threats)
            
            if threats:
                self.stats["files_with_threats"] += 1
            
        except Exception as e:
            self.logger.logger.error(f"Error scanning {filepath}: {e}")
        
        return threats
    
    def is_whitelisted(self, content: str) -> bool:
        """Check if content matches whitelist patterns"""
        for pattern in self.config.whitelist_regex:
            if pattern.search(content):
                return True
        return False
    
    def apply_detection_rules(self, filepath: str, content: str) -> List[Dict]:
        """Apply configured detection rules to content"""
        threats = []
        
        for i, line in enumerate(content.splitlines(), 1):
            # Skip obvious comments
            stripped = line.strip()
            if stripped.startswith(('//', '#', '/*', '*/', '*')):
                continue
            
            for rule in self.config.rules:
                if rule.regex.search(line):
                    # Additional context validation for advanced mode
                    if self.config.detection_level == "advanced":
                        if not self.validate_context(line, rule):
                            continue
                    
                    threat = self.logger.log_threat(
                        rule=rule,
                        filepath=filepath,
                        line_num=i,
                        line_content=line.strip(),
                        context={"detection_method": "rule_based"}
                    )
                    threats.append(threat)
                    self.stats["rules_triggered"][rule.name] += 1
        
        return threats
    
    def validate_context(self, line: str, rule: DetectionRule) -> bool:
        """Advanced context validation to reduce false positives"""
        
        # Skip if it's a comment with the pattern
        if re.match(r'\s*(//|#|/\*).*' + rule.pattern, line):
            return False
        
        # Skip common development patterns
        dev_patterns = [
            r'//\s*TODO:',
            r'//\s*FIXME:',
            r'//\s*DEBUG:',
            r'/\*\s*test\s*\*/',
        ]
        
        for pattern in dev_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return False
        
        return True
    
    def apply_heuristics(self, filepath: str, content: str) -> List[Dict]:
        """Apply heuristic analysis"""
        threats = []
        
        # 1. Entropy analysis for obfuscation
        if self.config.settings.get("check_entropy", False):
            entropy_threats = self.check_entropy(filepath, content)
            threats.extend(entropy_threats)
        
        # 2. Known malware signatures
        if self.config.settings.get("check_malware_signatures", False):
            signature_threats = self.check_malware_signatures(filepath, content)
            threats.extend(signature_threats)
        
        # 3. Dynamic code execution patterns
        if self.config.settings.get("check_dynamic_execution", False):
            dynamic_threats = self.check_dynamic_execution(filepath, content)
            threats.extend(dynamic_threats)
        
        return threats
    
    def check_entropy(self, filepath: str, content: str) -> List[Dict]:
        """Check for high entropy (obfuscated code)"""
        threats = []
        
        # Find long strings (potential obfuscated payloads)
        string_pattern = r'[\'"]([A-Za-z0-9+/=\-\_]{50,})[\'"]'
        for match in re.finditer(string_pattern, content):
            string_content = match.group(1)
            entropy = self.threat_intel.calculate_entropy(string_content)
            
            if entropy > self.config.settings.get("entropy_threshold", 4.5):
                threat = DetectionRule(
                    name="HIGH_ENTROPY_STRING",
                    pattern=string_pattern,
                    severity="medium",
                    description=f"High entropy string detected (entropy: {entropy:.2f})",
                    confidence=0.75,
                    tags=["obfuscation", "entropy"]
                )
                
                threats.append(self.logger.log_threat(
                    rule=threat,
                    filepath=filepath,
                    context={
                        "entropy": entropy,
                        "string_preview": string_content[:50],
                        "detection_method": "heuristic"
                    }
                ))
        
        return threats
    
    def check_malware_signatures(self, filepath: str, content: str) -> List[Dict]:
        """Check for known malware signatures"""
        threats = []
        
        for malware_type, signatures in self.threat_intel.MALWARE_SIGNATURES.items():
            for pattern, description in signatures:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = DetectionRule(
                        name=f"MALWARE_{malware_type.upper()}",
                        pattern=pattern,
                        severity="high",
                        description=f"{malware_type}: {description}",
                        confidence=0.85,
                        tags=["malware", malware_type.lower()]
                    )
                    
                    threats.append(self.logger.log_threat(
                        rule=threat,
                        filepath=filepath,
                        context={
                            "malware_type": malware_type,
                            "description": description,
                            "detection_method": "signature"
                        }
                    ))
        
        return threats
    
    def check_dynamic_execution(self, filepath: str, content: str) -> List[Dict]:
        """Check for dynamic code execution patterns"""
        threats = []
        
        # Dynamic function calls with variable names
        dynamic_patterns = [
            (r'(\$\w+)\s*\(\s*(\$\w+|[\'"])', "Dynamic function call"),
            (r'call_user_func.*\$_(GET|POST)', "call_user_func with user input"),
            (r'create_function.*\$', "create_function with dynamic code"),
        ]
        
        for pattern, description in dynamic_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                threat = DetectionRule(
                    name="DYNAMIC_EXECUTION_ADV",
                    pattern=pattern,
                    severity="medium",
                    description=f"Dynamic execution: {description}",
                    confidence=0.70,
                    tags=["dynamic-code", "execution"]
                )
                
                threats.append(self.logger.log_threat(
                    rule=threat,
                    filepath=filepath,
                    context={
                        "pattern": description,
                        "match": match.group()[:100],
                        "detection_method": "heuristic"
                    }
                ))
        
        return threats
    
    def scan_directory(self, directory: str) -> Dict:
        """Scan entire directory recursively (robust version)"""
        start_time = time.time()
        all_threats = []

        print(f"\nScanning directory: {directory}")
        print("-" * 50)

        try:
            for root, dirs, files in os.walk(directory):
                # --- Nettoyage propre des dossiers à ignorer ---
                dirs[:] = [
                    d for d in dirs
                    if not self.should_skip_dir(os.path.join(root, d))
                ]

                for file in files:
                    try:
                        if not self.should_scan_file(file):
                            continue

                        filepath = os.path.join(root, file)

                        # Vérifier que c'est bien un fichier régulier
                        if not os.path.isfile(filepath):
                            continue

                        file_threats = self.scan_file(filepath)
                        all_threats.extend(file_threats)

                        # Indicateur de progression
                        if self.stats["files_scanned"] % 100 == 0:
                            print(f"  Scanned {self.stats['files_scanned']} files...")

                    except Exception as e:
                        # On log mais on continue le scan
                        self.logger.logger.error(
                            f"Error scanning file {os.path.join(root, file)}: {e}"
                        )
                        continue

        except Exception as e:
            self.logger.logger.error(f"Error scanning directory {directory}: {e}")

        self.stats["execution_time"] = time.time() - start_time

        return {
            "threats": all_threats,
            "stats": self.stats.copy()
        }

    
    def should_skip_dir(self, dirpath: str) -> bool:
        """Check if directory should be skipped"""
        skip_patterns = [
            '/vendor/', '/node_modules/', '/.git/', '/cache/', 
            '/tmp/', '/temp/', '/log/', '/logs/'
        ]
        return any(pattern in dirpath for pattern in skip_patterns)
    
    def should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned based on extension"""
        extensions = ['.php', '.php3', '.php4', '.php5', '.php7', '.phtml']
        
        # In simple mode, also scan other file types
        if self.config.detection_level == "simple":
            extensions.extend(['.txt', '.html', '.htm', '.js', '.inc'])
        
        return any(filename.lower().endswith(ext) for ext in extensions)
    
    def print_stats(self):
        """Print scanning statistics"""
        print("\n" + "="*50)
        print("SCANNING STATISTICS")
        print("="*50)
        print(f"Files scanned: {self.stats['files_scanned']}")
        print(f"Files with threats: {self.stats['files_with_threats']}")
        print(f"Execution time: {self.stats['execution_time']:.2f}s")
        
        if self.stats["rules_triggered"]:
            print("\nRules triggered:")
            for rule, count in sorted(self.stats["rules_triggered"].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {rule}: {count}")


# ====================================================================
# ENHANCED LOG ANALYZER WITH PATTERN LEARNING
# ====================================================================

class EnhancedLogAnalyzer:
    """Advanced log analyzer with pattern learning"""
    
    def __init__(self, config: EnhancedConfig, logger: ThreatLogger):
        self.config = config
        self.logger = logger
        
        # Attack patterns with severity
        self.attack_patterns = {
            "critical": [
                (r'/etc/passwd.*HTTP', "LFI: /etc/passwd access attempt"),
                (r'php://filter.*read=', "PHP wrapper exploitation"),
                (r'union.*select.*from', "SQL Injection: UNION SELECT"),
                (r'<script>.*alert.*</script>', "XSS: Script injection"),
            ],
            "high": [
                (r'\.\./\.\./', "Path traversal attempt"),
                (r'waitfor.*delay.*\'', "SQL Injection: Time-based"),
                (r'benchmark\(.*,', "SQL Injection: Benchmark"),
                (r'%3Cscript%3E', "XSS: URL encoded script"),
            ],
            "medium": [
                (r'\/wp-admin', "WordPress admin access"),
                (r'\/administrator', "Joomla admin access"),
                (r'POST.*\.php.*\d{3}.*\d{10}', "Large POST request"),
                (r'404.*\.php\?.*=', "404 on PHP with parameters"),
            ]
        }
        
        # Learning: track frequencies
        self.pattern_frequencies = defaultdict(int)
        
    def analyze_log_file(self, log_file: str, max_lines: int = 10000):
        """Analyze a log file for attack patterns"""
        if not os.path.exists(log_file):
            self.logger.logger.warning(f"Log file not found: {log_file}")
            return
        
        print(f"\nAnalyzing log: {log_file}")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Read last N lines
                lines = f.readlines()[-max_lines:]
            
            attack_count = 0
            
            for i, line in enumerate(lines, 1):
                line = self.normalize_line(line)
                
                for severity, patterns in self.attack_patterns.items():
                    for pattern, description in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            attack_count += 1
                            
                            # Create threat entry
                            threat = DetectionRule(
                                name=f"LOG_ATTACK_{severity.upper()}",
                                pattern=pattern,
                                severity=severity,
                                description=f"Log attack: {description}",
                                confidence=0.80,
                                tags=["log-analysis", "attack"]
                            )
                            
                            self.logger.log_threat(
                                rule=threat,
                                filepath=log_file,
                                line_num=i,
                                line_content=line[:200],
                                context={
                                    "log_file": log_file,
                                    "attack_type": description,
                                    "severity": severity
                                }
                            )
                            
                            # Update frequency
                            self.pattern_frequencies[pattern] += 1
            
            if attack_count > 0:
                print(f"  Detected {attack_count} attack patterns")
            else:
                print(f"  No attack patterns detected")
                
        except Exception as e:
            self.logger.logger.error(f"Error analyzing log {log_file}: {e}")
    
    def normalize_line(self, line: str) -> str:
        """Normalize log line (URL decode, etc.)"""
        try:
            # Simple URL decoding
            for _ in range(2):
                line = urllib.parse.unquote(line)
        except:
            pass
        
        return line
    
    def analyze_all_logs(self):
        """Analyze all configured log paths"""
        for log_path in self.config.log_paths:
            if os.path.isdir(log_path):
                for root, dirs, files in os.walk(log_path):
                    for file in files:
                        if file.endswith(('.log', '.access.log', '.error.log')):
                            self.analyze_log_file(os.path.join(root, file))
            elif os.path.isfile(log_path):
                self.analyze_log_file(log_path)


# ====================================================================
# MAIN MONITOR CLASS
# ====================================================================

class PHPExpertSecurityMonitor:
    """Main monitor class with multi-level detection"""
    
    def __init__(self, detection_level: str = "advanced"):
        self.config = EnhancedConfig(detection_level)
        self.logger = ThreatLogger(self.config)
        self.file_scanner = EnhancedFileScanner(self.config, self.logger)
        self.log_analyzer = EnhancedLogAnalyzer(self.config, self.logger)
        self.baseline_manager = FileBaselineManager(self.config)  # <-- AJOUT IMPORTANT        
        
        # Create directories
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self.config.snapshot_dir.mkdir(parents=True, exist_ok=True)
        
    def run_simple_scan(self):
        """Run simple detection scan (fast, broad)"""
        print("\n" + "="*70)
        print("PHP SECURITY MONITOR v4.0 - SIMPLE DETECTION MODE")
        print("="*70)
        print("Mode: Fast scanning with broad detection rules")
        print("      Higher false positives, comprehensive coverage")
        print("="*70)
        
        start_time = time.time()
        
        # Scan all PHP paths
        for path in self.config.php_paths:
            if os.path.exists(path):
                self.file_scanner.scan_directory(path)
        
        # Basic log analysis
        self.log_analyzer.analyze_all_logs()
        
        # Print results
        self.print_results(start_time)
    
    def run_advanced_scan(self):
        """Run advanced detection scan (thorough, precise)"""
        print("\n" + "="*70)
        print("PHP SECURITY MONITOR v4.0 - ADVANCED DETECTION MODE")
        print("="*70)
        print("Mode: Thorough scanning with precise detection")
        print("      Lower false positives, heuristic analysis")
        print("="*70)
        
        start_time = time.time()
        
        # Phase 1: Rule-based scanning
        print("\n[PHASE 1] Rule-based detection")
        print("-" * 40)
        for path in self.config.php_paths:
            if os.path.exists(path):
                self.file_scanner.scan_directory(path)
        
        # Phase 2: Heuristic analysis
        print("\n[PHASE 2] Heuristic analysis")
        print("-" * 40)
        # (Already integrated in file scanner for advanced mode)
        
        # Phase 3: Log analysis with pattern learning
        print("\n[PHASE 3] Log analysis")
        print("-" * 40)
        self.log_analyzer.analyze_all_logs()
        
        # Phase 4: System checks (permissions, etc.)
        print("\n[PHASE 4] System integrity checks")
        print("-" * 40)
        self.check_system_integrity()

        # Phase 5: System checks (permissions, etc.)
        print("\n[PHASE 5] Baseline integrity check")
        print("-" * 40)
        self.check_baseline_changes()

        
        # Print results
        self.print_results(start_time)
    
    def check_system_integrity(self):
        """Check system file integrity"""
        print("Checking file permissions...")
        
        dangerous_perms = []
        for path in self.config.php_paths:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith('.php'):
                        filepath = os.path.join(root, file)
                        try:
                            perm = oct(os.stat(filepath).st_mode)[-3:]
                            if perm in ['777', '776', '775', '774']:
                                dangerous_perms.append((filepath, perm))
                        except:
                            pass
        
        if dangerous_perms:
            print(f"  Found {len(dangerous_perms)} files with dangerous permissions")
            for filepath, perm in dangerous_perms[:5]:
                print(f"    {filepath} - {perm}")
        
        print("System integrity check completed")

    def create_baseline(self):
        """Create a new baseline of PHP files"""
        print("\n[+] Creating baseline...")
        self.baseline_manager.create_baseline(self.config.php_paths)
        print("[+] Baseline created.")

# Corrigez-la ainsi :
    def check_baseline_changes(self):
        """Check for changes compared to baseline"""
        if not hasattr(self, 'baseline_manager'):
            self.baseline_manager = FileBaselineManager(self.config)
        
        changes = self.baseline_manager.compare_with_baseline(self.config.php_paths)
        
        if changes["modified"] or changes["new"] or changes["deleted"]:
            # Log threats for significant changes
            for filepath in changes["modified"]:
                threat = DetectionRule(
                    name="FILE_MODIFIED",
                    pattern="",
                    severity="medium",
                    description="File modified since baseline",
                    confidence=0.75,
                    tags=["baseline", "integrity"]
                )
                self.logger.log_threat(
                    rule=threat,
                    filepath=filepath,
                    context={"change_type": "modified"}
                )


    def print_results(self, start_time: float):
        """Print scan results"""
        duration = time.time() - start_time
        
        # Print statistics
        self.file_scanner.print_stats()
        
        # Print threat summary
        self.logger.print_summary()
        
        # Final recommendations
        print("\n" + "="*70)
        print("RECOMMENDATIONS")
        print("="*70)
        
        summary = self.logger.get_summary()
        
        if summary["total_threat_score"] == 0:
            print("✅ No significant threats detected")
            print("✅ System appears clean")
        elif summary["total_threat_score"] < 10:
            print("⚠️  Low risk threats detected")
            print("⚠️  Review threats in log files")
        elif summary["total_threat_score"] < 30:
            print("⚠️  Medium risk threats detected")
            print("⚠️  Immediate review recommended")
            print("⚠️  Check critical and high severity threats first")
        else:
            print("🚨 HIGH RISK THREATS DETECTED")
            print("🚨 IMMEDIATE ACTION REQUIRED")
            print("🚨 Isolate affected systems if possible")
        
        print(f"\nScan completed in {duration:.2f} seconds")
        print("="*70)





# ====================================================================
# COMMAND LINE INTERFACE
# ====================================================================

def main():
    """Main entry point with command line arguments"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PHP Security Monitor v4.0 - Expert Cybersecurity Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(pro)s --level simple      # Fast scan with broad detection
  %(pro)s --level advanced    # Thorough scan with heuristics
  %(pro)s --config /path/to/config.conf  # Custom config
  %(pro)s --path /var/www/html --level advanced  # Scan specific path
        """
    )
    
    parser.add_argument("--level", "-l", 
                       choices=["simple", "advanced"],
                       default="advanced",
                       help="Detection level (default: advanced)")
    
    parser.add_argument("--config", "-c",
                       type=str,
                       help="Custom configuration file path")
    
    parser.add_argument("--path", "-p",
                       type=str,
                       help="Specific path to scan (overrides config)")
    
    parser.add_argument("--create-baseline", 
                       action="store_true",
                       help="Create initial file baseline")
    
    parser.add_argument("--update-baseline",
                       action="store_true",
                       help="Update existing baseline")
    
    parser.add_argument("--quiet", "-q",
                       action="store_true",
                       help="Suppress non-essential output")
    
    args = parser.parse_args()
    
    # Check root privileges
    if os.geteuid() != 0:
        print("ERROR: Root privileges required")
        print("Run: sudo python3 php_monitor_v4.py")
        sys.exit(1)
    
    try:
        # Initialize monitor
        monitor = PHPExpertSecurityMonitor(detection_level=args.level)
        
        # Override paths if specified
        if args.path:
            monitor.config.php_paths = [args.path]
        
        # Override config if specified
        if args.config:
            monitor.config.config_file = Path(args.config)
            monitor.config.load_config()
        
        # Run appropriate scan
        if args.level == "simple":
            monitor.run_simple_scan()
        else:
            monitor.run_advanced_scan()
        
        # Exit with appropriate code
        summary = monitor.logger.get_summary()
        if summary["total_threat_score"] > 20:
            sys.exit(2)  # High risk
        elif summary["total_threat_score"] > 0:
            sys.exit(1)  # Low/medium risk
        else:
            sys.exit(0)  # Clean
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Install python-magic if needed
    try:
        import magic
    except ImportError:
        print("Installing required package: python-magic")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-magic"])
        import magic
    
    
    main()