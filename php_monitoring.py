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
import mysql.connector
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
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
    
    def __init__(self, detection_level: str = "advanced", user: str = None):
        self.detection_level = detection_level
        self.user = user
        self.config_file = Path("/etc/php_monitor_v4.conf")
        
        # Base directories
        base_log_dir = Path("/var/log/php_monitor_v4")
        base_lib_dir = Path("/var/lib/php_monitor_v4")
        
        # User-specific paths if user is provided
        user_suffix = f"_{user}" if user else ""
        self.log_dir = base_log_dir / f"logs{user_suffix}"
        self.snapshot_dir = base_lib_dir / f"snapshots{user_suffix}"
        self.baseline_file = base_lib_dir / f"baseline{user_suffix}.json"
        self.threat_db_file = base_lib_dir / f"threats{user_suffix}.json"
        
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
        
        # Email configuration
        self.email_config = {
            'enabled': False,
            'smtp_server': 'localhost',
            'smtp_port': 587,
            'smtp_user': '',
            'smtp_password': '',
            'from_addr': 'php-monitor@localhost',
            'to_addr': ''
        }
        
        # Database parameters
        self.db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': '',
            'database': '',
            'target_tables': []
        }
        
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
                    
                    # 1. Load user and detection level first (they affect paths)
                    if 'user' in section and not self.user:
                        self.user = section['user']
                        # Update paths if user was found in config and not passed in CLI
                        user_suffix = f"_{self.user}" if self.user else ""
                        base_log_dir = Path("/var/log/php_monitor_v4")
                        base_lib_dir = Path("/var/lib/php_monitor_v4")
                        self.log_dir = base_log_dir / f"logs{user_suffix}"
                        self.snapshot_dir = base_lib_dir / f"snapshots{user_suffix}"
                        self.baseline_file = base_lib_dir / f"baseline{user_suffix}.json"
                        self.threat_db_file = base_lib_dir / f"threats{user_suffix}.json"

                    if 'detection_level' in section:
                        self.detection_level = section['detection_level']
                        self.settings = self.DETECTION_LEVELS.get(
                            self.detection_level, 
                            self.DETECTION_LEVELS["advanced"]
                        )

                    # 2. Load paths with user replacement
                    list_fields = ['php_paths', 'log_paths', 'sensitive_dirs']
                    for field in list_fields:
                        if field in section:
                            paths = json.loads(section[field])
                            if self.user:
                                paths = [p.replace("{user}", self.user) for p in paths]
                            setattr(self, field, paths)
                    
                    # 3. Update remaining settings
                    for key in ['recent_hours', 'max_file_size']:
                        if key in section:
                            setattr(self, key, int(section[key]))
                            
                if 'DATABASE' in config:
                    db_section = config['DATABASE']
                    for key in ['host', 'user', 'password', 'database']:
                        if key in db_section:
                            self.db_config[key] = db_section[key]
                    if 'target_tables' in db_section:
                        self.db_config['target_tables'] = json.loads(db_section['target_tables'])
                    if 'enabled' in db_section:
                        self.db_check_enabled = db_section.getboolean('enabled')
                
                if 'EMAIL' in config:
                    email_section = config['EMAIL']
                    if 'enabled' in email_section:
                        self.email_config['enabled'] = email_section.getboolean('enabled')
                    for key in ['smtp_server', 'smtp_user', 'smtp_password', 'from_addr', 'to_addr']:
                        if key in email_section:
                            self.email_config[key] = email_section[key]
                    if 'smtp_port' in email_section:
                        self.email_config['smtp_port'] = int(email_section['smtp_port'])
                            
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
        """Crée une baseline des fichiers"""
        print("\n[+] Création de la baseline des fichiers...")

        baseline = {}
        file_scanner = EnhancedFileScanner(self.config, ThreatLogger(self.config))

        for path in paths:
            for root, dirs, files in os.walk(path):
                # Filtrer les dossiers à ignorer
                dirs[:] = [d for d in dirs if not any(x in os.path.join(root, d) for x in [
                    "/vendor/", "/node_modules/", "/.git/", "/cache/", "/tmp/"
                ])]

                for file in files:
                    # Utiliser la même logique que should_scan_file
                    if file_scanner.should_scan_file(file):
                        filepath = os.path.join(root, file)
                        try:
                            baseline[filepath] = self.compute_file_hash(filepath)
                        except Exception as e:
                            print(f"[-] Erreur hash {filepath}: {e}")

        with open(self.baseline_file, "w") as f:
            json.dump(baseline, f, indent=2)

        print(f"[+] Baseline créée avec {len(baseline)} fichiers : {self.baseline_file}")
        return baseline

    def load_baseline(self) -> Dict[str, str]:
        if not self.baseline_file.exists():
            print("[-] Aucune baseline trouvée !")
            return {}

        with open(self.baseline_file, "r") as f:
            return json.load(f)

    def compare_with_baseline(self, current_paths: List[str]) -> Dict[str, List[str]]:
        """Compare l'état actuel avec la baseline"""
        print("\n[+] Comparaison avec la baseline...")

        baseline = self.load_baseline()
        if not baseline:
            return {"modified": [], "deleted": [], "new": []}
        
        current_files = {}
        modified = []
        deleted = []
        new_files = []

        # Scanner les fichiers actuels avec la même logique que le scanner
        file_scanner = EnhancedFileScanner(self.config, ThreatLogger(self.config))
        
        for path in current_paths:
            for root, dirs, files in os.walk(path):
                # Filtrer les dossiers à ignorer
                dirs[:] = [d for d in dirs if not any(x in os.path.join(root, d) for x in [
                    "/vendor/", "/node_modules/", "/.git/", "/cache/", "/tmp/"
                ])]

                for file in files:
                    if file_scanner.should_scan_file(file):
                        filepath = os.path.join(root, file)
                        try:
                            current_files[filepath] = self.compute_file_hash(filepath)
                        except Exception as e:
                            print(f"[-] Erreur hash {filepath}: {e}")
                            continue

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

        print(f"  Total dans baseline: {len(baseline)} fichiers")
        print(f"  Total actuels: {len(current_files)} fichiers")
        
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
    
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Sécurité PHP - {user}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; background-color: #f4f7f6; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
            .summary-box {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
            .stat-number {{ font-size: 24px; font-weight: bold; margin-bottom: 5px; }}
            .stat-label {{ color: #666; font-size: 14px; text-transform: uppercase; }}
            .perf-section {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 30px; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .perf-item {{ text-align: center; }}
            .perf-value {{ font-size: 18px; font-weight: bold; margin-bottom: 5px; }}
            .perf-bar-bg {{ background: #eee; height: 10px; border-radius: 5px; overflow: hidden; margin-top: 5px; }}
            .perf-bar-fill {{ height: 100%; border-radius: 5px; transition: width 0.5s ease; }}
            .bar-low {{ background: #2ecc71; }}
            .bar-med {{ background: #f1c40f; }}
            .bar-high {{ background: #e74c3c; }}
            .threat-list {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .threat-item {{ border-left: 5px solid #eee; padding: 15px; margin-bottom: 15px; background: #fafafa; }}
            .threat-item.critical {{ border-left-color: #e74c3c; background: #fdf2f2; }}
            .threat-item.high {{ border-left-color: #e67e22; background: #fef5e7; }}
            .threat-item.medium {{ border-left-color: #f1c40f; background: #fef9e7; }}
            .threat-item.low {{ border-left-color: #3498db; background: #ebf5fb; }}
            .severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 10px; }}
            .critical .severity-badge {{ background: #e74c3c; color: white; }}
            .high .severity-badge {{ background: #e67e22; color: white; }}
            .file-path {{ font-family: monospace; color: #2980b9; word-break: break-all; }}
            .description {{ font-weight: bold; margin: 5px 0; }}
            .code-snippet {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; margin-top: 10px; overflow-x: auto; font-size: 13px; }}
            .no-threats {{ text-align: center; padding: 50px; color: #27ae60; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1 style="margin:0">Rapport de Sécurité PHP</h1>
                <p style="margin:5px 0 0 0">Utilisateur: {user} | {date}</p>
            </div>
            <div style="text-align:right">
                <div style="font-size:12px">Score Total</div>
                <div style="font-size:32px; font-weight:bold">{score}</div>
            </div>
        </div>

        <div class="summary-box">
            <div class="stat-card">
                <div class="stat-number" style="color:#e74c3c">{critical_count}</div>
                <div class="stat-label">Critiques</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:#e67e22">{high_count}</div>
                <div class="stat-label">Élevées</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{medium_count}</div>
                <div class="stat-label">Moyennes</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{files_scanned}</div>
                <div class="stat-label">Fichiers Scannés</div>
            </div>
        </div>

        <h2 style="color:#2c3e50">Performance Système</h2>
        <div class="perf-section">
            <div class="perf-item">
                <div class="stat-label">CPU</div>
                <div class="perf-value">{cpu_usage}%</div>
                <div class="perf-bar-bg"><div class="perf-bar-fill {cpu_color}" style="width:{cpu_usage}%"></div></div>
            </div>
            <div class="perf-item">
                <div class="stat-label">RAM</div>
                <div class="perf-value">{ram_usage}%</div>
                <div class="perf-bar-bg"><div class="perf-bar-fill {ram_color}" style="width:{ram_usage}%"></div></div>
                <div style="font-size:11px; color:#666; margin-top:5px">{ram_used}MB / {ram_total}MB</div>
            </div>
            <div class="perf-item">
                <div class="stat-label">Disque</div>
                <div class="perf-value">{disk_usage}%</div>
                <div class="perf-bar-bg"><div class="perf-bar-fill {disk_color}" style="width:{disk_usage}%"></div></div>
                <div style="font-size:11px; color:#666; margin-top:5px">{disk_used}MB / {disk_total}MB</div>
            </div>
        </div>

        <div class="threat-list">
            <h2>Détails des menaces détectées</h2>
            {threat_details}
        </div>
        
        <p style="text-align:center; color:#95a5a6; font-size:12px; margin-top:30px">
            Généré par PHP SECURITY MONITOR v4.0
        </p>
    </body>
    </html>
    """
    
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
        self.html_report_file = self.log_dir / f"report_{timestamp}.html"
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
    
    def generate_reports(self, stats: Dict = None):
        """Génère les rapports finaux (TXT et HTML)"""
        self.generate_html_report(stats)
        print(f"[+] Rapport HTML généré : {self.html_report_file}")
        print(f"[+] Rapport TXT généré : {self.report_file}")
        
        # Envoi de l'email si configuré
        if self.config.email_config['enabled'] and self.config.email_config['to_addr']:
            self.send_email_report()

    def send_email_report(self):
        """Envoie le rapport par email"""
        print(f"[+] Envoi du rapport par email à {self.config.email_config['to_addr']}...")
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.email_config['from_addr']
            msg['To'] = self.config.email_config['to_addr']
            msg['Subject'] = f"Alerte Sécurité PHP : {sum(len(v) for v in self.threats_by_severity.values())} menaces détectées"
            
            # Corps du mail (texte simple)
            summary = self.get_summary()
            body = f"Le scan de sécurité PHP est terminé pour l'utilisateur {self.config.user or 'Système'}.\n\n"
            body += f"Score de menace total : {summary['total_threat_score']}\n"
            body += f"Menaces Critiques : {len(self.threats_by_severity.get('critical', []))}\n"
            body += f"Menaces Élevées : {len(self.threats_by_severity.get('high', []))}\n"
            body += f"Menaces Moyennes : {len(self.threats_by_severity.get('medium', []))}\n\n"
            body += "Veuillez trouver le rapport détaillé en pièce jointe."
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Pièce jointe HTML
            if self.html_report_file.exists():
                with open(self.html_report_file, "rb") as f:
                    part = MIMEApplication(f.read(), Name=self.html_report_file.name)
                part['Content-Disposition'] = f'attachment; filename="{self.html_report_file.name}"'
                msg.attach(part)
            
            # Envoi via SMTP
            server = smtplib.SMTP(self.config.email_config['smtp_server'], self.config.email_config['smtp_port'])
            server.starttls()
            
            if self.config.email_config['smtp_user'] and self.config.email_config['smtp_password']:
                server.login(self.config.email_config['smtp_user'], self.config.email_config['smtp_password'])
            
            server.send_message(msg)
            server.quit()
            print("[+] Email envoyé avec succès.")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi de l'email : {e}")
            print(f"[-] Erreur lors de l'envoi de l'email : {e}")

    def generate_html_report(self, stats: Dict = None):
        """Génère un rapport HTML élégant et simple"""
        
        threat_details = ""
        relevant_severities = ["critical", "high", "medium"]
        
        # Performance data
        perf = stats.get("perf", {"cpu": 0, "ram": {"percent": 0, "used": 0, "total": 0}, "disk": {"percent": 0, "used": 0, "total": 0}})
        
        def get_color(percent):
            if percent < 60: return "bar-low"
            if percent < 85: return "bar-med"
            return "bar-high"

        # Collecter toutes les menaces importantes
        all_threats = []
        for sev in relevant_severities:
            all_threats.extend(self.threats_by_severity.get(sev, []))
        
        # Trier par sévérité (Critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        all_threats.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        if not all_threats:
            threat_details = '<div class="no-threats"><h3>Aucune menace importante détectée. Le système semble sain.</h3></div>'
        else:
            for threat in all_threats:
                code_block = ""
                if 'content' in threat and threat['content']:
                    code_block = f'<div class="code-snippet">{threat["content"]}</div>'
                
                line_info = f" (Ligne {threat['line']})" if threat.get('line') else ""
                
                threat_details += f"""
                <div class="threat-item {threat['severity']}">
                    <span class="severity-badge">{threat['severity']}</span>
                    <div class="description">{threat['rule']}: {threat['description']}</div>
                    <div class="file-path">{threat['file']}{line_info}</div>
                    {code_block}
                </div>
                """
        
        html_content = self.HTML_TEMPLATE.format(
            user=self.config.user or "Système",
            date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            score=self.total_threat_score,
            critical_count=len(self.threats_by_severity.get("critical", [])),
            high_count=len(self.threats_by_severity.get("high", [])),
            medium_count=len(self.threats_by_severity.get("medium", [])),
            files_scanned=stats.get("files_scanned", 0) if stats else "N/A",
            threat_details=threat_details,
            # Performance fields
            cpu_usage=perf["cpu"],
            cpu_color=get_color(perf["cpu"]),
            ram_usage=perf["ram"]["percent"],
            ram_used=perf["ram"]["used"],
            ram_total=perf["ram"]["total"],
            ram_color=get_color(perf["ram"]["percent"]),
            disk_usage=perf["disk"]["percent"],
            disk_used=perf["disk"]["used"],
            disk_total=perf["disk"]["total"],
            disk_color=get_color(perf["disk"]["percent"])
        )
        
        with open(self.html_report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

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
        """Vérifie si un fichier doit être scanné"""
        # Extensions PHP
        php_extensions = ['.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.phps']
        
        # Autres extensions potentiellement dangereuses
        other_extensions = ['.inc', '.php.inc', '.module', '.plugin']
        
        # Fichiers sans extension ou avec extension suspecte
        suspicious_patterns = [
            r'^\.ht',  # Fichiers .htaccess, etc.
            r'config\.',  # Fichiers de configuration
            r'web\.config',
            r'wp-config\.php',
        ]
        
        # Vérifier les extensions PHP
        if any(filename.lower().endswith(ext) for ext in php_extensions):
            return True
        
        # Vérifier les autres extensions
        if self.config.detection_level == "advanced":
            if any(filename.lower().endswith(ext) for ext in other_extensions):
                return True
            
            # Vérifier les motifs suspects
            for pattern in suspicious_patterns:
                if re.search(pattern, filename, re.IGNORECASE):
                    return True
        
        # Mode simple: inclure plus de types de fichiers
        if self.config.detection_level == "simple":
            simple_extensions = ['.txt', '.html', '.htm', '.js', '.json', '.xml']
            if any(filename.lower().endswith(ext) for ext in simple_extensions):
                return True
        
        return False
    
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
# DATABASE SCANNER
# ====================================================================

class DatabaseScanner:
    """Scanner for malicious content in database tables"""
    
    def __init__(self, config: EnhancedConfig, logger: ThreatLogger):
        self.config = config
        self.logger = logger
        self.db_config = config.db_config
        
    def scan_database(self):
        """Scan configured database tables for threats"""
        if not self.config.db_check_enabled:
            return
            
        if not self.db_config['database'] or not self.db_config['target_tables']:
            self.logger.logger.warning("Database scanning enabled but no database or tables configured.")
            return
            
        print(f"\nScanning database: {self.db_config['database']}")
        print("-" * 50)
        
        try:
            conn = mysql.connector.connect(
                host=self.db_config['host'],
                user=self.db_config['user'],
                password=self.db_config['password'],
                database=self.db_config['database']
            )
            cursor = conn.cursor(dictionary=True)
            
            for table in self.db_config['target_tables']:
                self.scan_table(cursor, table)
                
            cursor.close()
            conn.close()
            
        except mysql.connector.Error as err:
            self.logger.logger.error(f"Database error: {err}")
        except Exception as e:
            self.logger.logger.error(f"Unexpected error during database scan: {e}")
            
    def scan_table(self, cursor, table: str):
        """Scan all columns of a table for malicious patterns"""
        print(f"  Scanning table: {table}...")
        
        try:
            # Get text-based columns
            cursor.execute(f"SHOW COLUMNS FROM `{table}`")
            columns = [row['Field'] for row in cursor.fetchall() 
                       if any(t in row['Type'].lower() for t in ['char', 'text', 'blob'])]
            
            if not columns:
                return
                
            # Fetch all rows (limit to avoid memory issues if huge, though dictionary=True might be slow)
            cursor.execute(f"SELECT * FROM `{table}`")
            rows = cursor.fetchall()
            
            for row in rows:
                for col in columns:
                    content = str(row[col]) if row[col] else ""
                    if not content:
                        continue
                        
                    self.check_content(content, table, col, row)
                    
        except Exception as e:
            self.logger.logger.error(f"Error scanning table {table}: {e}")
            
    def check_content(self, content: str, table: str, col: str, row: Dict):
        """Check string content for malicious patterns"""
        # We reuse some rules from the file scanner
        for rule in self.config.rules:
            if rule.regex.search(content):
                primary_key = list(row.keys())[0] # Guessing first col is PK
                pk_val = row[primary_key]
                
                self.logger.log_threat(
                    rule=rule,
                    filepath=f"DB:{self.db_config['database']}.{table}",
                    line_content=f"Table: {table}, Column: {col}, PK({primary_key}): {pk_val}",
                    context={
                        "detection_method": "db_scan",
                        "table": table,
                        "column": col,
                        "pk_value": pk_val
                    }
                )


class PerformanceMonitor:
    """Monitor system performance (CPU, RAM, Disk) using system commands"""
    
    @staticmethod
    def get_cpu_usage() -> float:
        try:
            # Using 'top' to get load average as a fallback or proxy for CPU usage
            cmd = "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\([0-9.]*\)%* id.*/\\1/' | awk '{print 100 - $1}'"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            return float(output)
        except:
            return 0.0

    @staticmethod
    def get_ram_usage() -> Dict[str, float]:
        try:
            cmd = "free -m | grep Mem"
            output = subprocess.check_output(cmd, shell=True).decode().split()
            total = float(output[1])
            used = float(output[2])
            percent = (used / total) * 100
            return {"total": total, "used": used, "percent": round(percent, 1)}
        except:
            return {"total": 0, "used": 0, "percent": 0}

    @staticmethod
    def get_disk_usage(path="/") -> Dict[str, float]:
        try:
            cmd = f"df -m {path} | tail -1"
            output = subprocess.check_output(cmd, shell=True).decode().split()
            total = float(output[1])
            used = float(output[2])
            percent = float(output[4].replace('%', ''))
            return {"total": total, "used": used, "percent": percent}
        except:
            return {"total": 0, "used": 0, "percent": 0}

    def get_full_stats(self) -> Dict:
        return {
            "cpu": self.get_cpu_usage(),
            "ram": self.get_ram_usage(),
            "disk": self.get_disk_usage()
        }


# ====================================================================
# MAIN MONITOR CLASS
# ====================================================================

class PHPExpertSecurityMonitor:
    """Main monitor class with multi-level detection"""
    
    def __init__(self, detection_level: str = "advanced", user: str = None):
        self.config = EnhancedConfig(detection_level, user)
        self.logger = ThreatLogger(self.config)
        self.file_scanner = EnhancedFileScanner(self.config, self.logger)
        self.log_analyzer = EnhancedLogAnalyzer(self.config, self.logger)
        self.db_scanner = DatabaseScanner(self.config, self.logger)
        self.baseline_manager = FileBaselineManager(self.config)  # <-- AJOUT IMPORTANT        
        self.perf_monitor = PerformanceMonitor()
        
        # Create directories
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self.config.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def create_initial_baseline(self):
        """Crée la baseline initiale si elle n'existe pas"""
        if not self.baseline_manager.baseline_file.exists():
            print("\n[+] Création de la baseline initiale...")
            self.baseline_manager.create_baseline(self.config.php_paths)
            print(f"[+] Baseline créée : {self.baseline_manager.baseline_file}")
        else:
            print(f"[+] Baseline existante : {self.baseline_manager.baseline_file}")

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
        
        # Database analysis
        if self.config.db_check_enabled:
            self.db_scanner.scan_database()
        
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

        # Phase 6: Database content analysis
        if self.config.db_check_enabled:
            print("\n[PHASE 6] Database content analysis")
            print("-" * 40)
            self.db_scanner.scan_database()
        
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

    def ensure_baseline_exists(self):
        """Vérifie et crée la baseline si nécessaire"""
        if not self.baseline_manager.baseline_file.exists():
            print("\n[!] Aucune baseline trouvée.")
            print("[+] Création automatique de la baseline...")
            self.baseline_manager.create_baseline(self.config.php_paths)
            print("[+] Baseline créée avec succès.")
            return True
        return False

    def check_baseline_changes(self):
        """Vérifie les changements par rapport à la baseline"""
        # S'assurer que la baseline existe
        if not self.baseline_manager.baseline_file.exists():
            print("\n[-] Aucune baseline trouvée.")
            print("[+] Création de la baseline maintenant...")
            self.baseline_manager.create_baseline(self.config.php_paths)
            print("[+] Baseline créée. Relancez le scan pour détecter les changements.")
            return
        
        print("\n[+] Vérification des changements depuis la baseline...")
        
        try:
            changes = self.baseline_manager.compare_with_baseline(self.config.php_paths)
            
            if not any([changes['modified'], changes['new'], changes['deleted']]):
                print("  Aucun changement détecté depuis la baseline.")
                return
            
            # Afficher les résultats
            print(f"\n  RÉSULTATS:")
            print(f"  -----------")
            print(f"  Fichiers modifiés: {len(changes['modified'])}")
            print(f"  Fichiers nouveaux: {len(changes['new'])}")
            print(f"  Fichiers supprimés: {len(changes['deleted'])}")
            
            # Afficher les détails
            if changes['modified']:
                print(f"\n  Fichiers modifiés (premiers 10):")
                for i, file in enumerate(changes['modified'][:10], 1):
                    print(f"    {i}. {file}")
                if len(changes['modified']) > 10:
                    print(f"    ... et {len(changes['modified']) - 10} autres")
            
            if changes['new']:
                print(f"\n  Nouveaux fichiers (premiers 10):")
                for i, file in enumerate(changes['new'][:10], 1):
                    print(f"    {i}. {file}")
                if len(changes['new']) > 10:
                    print(f"    ... et {len(changes['new']) - 10} autres")
            
            # Loguer les menaces
            threat_count = 0
            for filepath in changes["modified"]:
                try:
                    current_hash = self.baseline_manager.compute_file_hash(filepath)
                    
                    threat = DetectionRule(
                        name="FILE_MODIFIED",
                        pattern="",
                        severity="medium",
                        description=f"Fichier modifié depuis la baseline",
                        confidence=0.85,
                        tags=["baseline", "integrity", "file-change"]
                    )
                    self.logger.log_threat(
                        rule=threat,
                        filepath=filepath,
                        context={
                            "change_type": "modified",
                            "hash_current_short": current_hash[:16],
                            "detection_method": "baseline_comparison"
                        }
                    )
                    threat_count += 1
                    
                except Exception as e:
                    self.logger.logger.error(f"Erreur lors du traitement de {filepath}: {e}")
            
            for filepath in changes["new"]:
                threat = DetectionRule(
                    name="NEW_FILE_DETECTED",
                    pattern="",
                    severity="low",
                    description="Nouveau fichier détecté",
                    confidence=0.70,
                    tags=["baseline", "new-file"]
                )
                self.logger.log_threat(
                    rule=threat,
                    filepath=filepath,
                    context={"change_type": "new"}
                )
                threat_count += 1
            
            if threat_count > 0:
                print(f"\n[+] {threat_count} changements détectés et logués comme menaces potentielles")
                
        except Exception as e:
            self.logger.logger.error(f"Erreur lors de la vérification de la baseline: {e}")
            print(f"[-] Erreur: {e}")


    def print_results(self, start_time: float):
        """Print scan results"""
        duration = time.time() - start_time
        
        # Collect performance metrics
        perf_stats = self.perf_monitor.get_full_stats()
        
        # Print statistics
        self.file_scanner.print_stats()
        
        # Generate and print threat summary
        combined_stats = {**self.file_scanner.stats, "perf": perf_stats}
        self.logger.generate_reports(combined_stats)
        self.logger.print_summary()
        
        # Final recommendations
        print("\n" + "="*70)
        print("RECOMMENDATIONS")
        print("="*70)
        
        summary = self.logger.get_summary()
        
        if summary["total_threat_score"] == 0:
            print("? No significant threats detected")
            print("? System appears clean")
        elif summary["total_threat_score"] < 10:
            print("??  Low risk threats detected")
            print("??  Review threats in log files")
        elif summary["total_threat_score"] < 30:
            print("??  Medium risk threats detected")
            print("??  Immediate review recommended")
            print("??  Check critical and high severity threats first")
        else:
            print("?? HIGH RISK THREATS DETECTED")
            print("?? IMMEDIATE ACTION REQUIRED")
            print("?? Isolate affected systems if possible")
        
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
    
    parser.add_argument("--user", "-u",
                       type=str,
                       help="Specific user for the scan")
    
    parser.add_argument("--email", "-e",
                       type=str,
                       help="Email address to send the report to")
    
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
        monitor = PHPExpertSecurityMonitor(detection_level=args.level, user=args.user)
        
        # Override email if specified in CLI
        if args.email:
            monitor.config.email_config['to_addr'] = args.email
            monitor.config.email_config['enabled'] = True
        
        # Gestion des baselines
        if args.create_baseline:
            print("\n[+] Création de la baseline...")
            monitor.baseline_manager.create_baseline(monitor.config.php_paths)
            print(f"[+] Baseline créée : {monitor.baseline_manager.baseline_file}")
            sys.exit(0)
        
        if args.update_baseline:
            print("\n[+] Mise à jour de la baseline...")
            monitor.baseline_manager.create_baseline(monitor.config.php_paths)
            print(f"[+] Baseline mise à jour : {monitor.baseline_manager.baseline_file}")
            sys.exit(0)
        
        # Avant de lancer le scan, vérifier si la baseline existe
        if monitor.config.detection_level == "advanced":
            if not monitor.baseline_manager.baseline_file.exists():
                print("\n[!] Aucune baseline trouvée.")
                response = input("Voulez-vous créer une baseline maintenant? (o/n): ")
                if response.lower() in ['o', 'oui', 'y', 'yes']:
                    monitor.baseline_manager.create_baseline(monitor.config.php_paths)
                    print("[+] Baseline créée. Relancez le scan pour la comparaison.")
                    sys.exit(0)

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
    # Install required packages if needed
    for package, import_name in [('python-magic', 'magic'), ('mysql-connector-python', 'mysql.connector')]:
        try:
            __import__(import_name)
        except ImportError:
            print(f"Installing required package: {package}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
    main()