#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP SECURITY MONITOR v3.1
Complete PHP server security monitoring - Python version
"""

import os
import sys
import re
import time
import hashlib
import subprocess
import configparser
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
import json
import logging
from logging.handlers import RotatingFileHandler

# ====================================================================
# CONFIGURATION
# ====================================================================

class Config:
    """Configuration management"""
    def __init__(self):
        self.config_file = Path("/etc/php_monitor.conf")
        self.log_dir = Path("/var/log/php_monitor")
        self.snapshot_dir = Path("/var/lib/php_monitor/snapshots")
        self.baseline_file = Path("/var/lib/php_monitor/baseline.json")
        
        # Default paths
        self.web_root = "/var/www/html"
        self.php_paths = ["/var/www/html"]
        self.log_paths = ["/var/log/apache2", "/var/log/nginx"]
        self.ftp_log = "/var/log/vsftpd.log"
        
        # Parameters
        self.recent_hours = 24
        self.max_file_size = 10485760  # 10MB
        self.db_check_enabled = False  # Désactivé par défaut pour la sécurité
        
        # Suspicious patterns with context awareness
        self.suspicious_functions = [
            r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)',
            r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'gzinflate\s*\(\s*base64_decode',
            r'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        ]
        
        # Base64 obfuscation patterns (plus spécifiques)
        self.suspicious_base64 = [
            r'[\'\"][A-Za-z0-9+/]{100,}[\'\"]\s*\)\s*;\s*eval',
            r'base64_decode\s*\(\s*[\'\"][A-Za-z0-9+/]{50,}[\'\"]\s*\)\s*;',
            r'eval\s*\(\s*gzinflate\s*\(\s*base64_decode',
        ]
        
        self.suspicious_tags = [
            r'<iframe[^>]*src\s*=\s*[\'\"](?!https?://)',
            r'<script[^>]*>\s*eval\s*\(',
            r'javascript:\s*(eval|document\.write)',
            r'onload\s*=\s*[\'\"].*eval',
            r'onerror\s*=\s*[\'\"].*eval',
            r'document\.write\s*\(\s*unescape\s*\(',
        ]
        
        # Whitelist pour éviter les faux positifs
        self.whitelist_patterns = [
            r'//\s*@ignore-security-scan',
            r'/\*\s*security-scan-ignore\s*\*/',
            r'Framework::',
            r'base64_decode\s*\(\s*[\'\"][A-Za-z0-9+/]{1,50}[\'\"]\s*\)\s*;',
        ]
        
        # Compile regex for performance
        self.suspicious_functions_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_functions
        ]
        self.suspicious_base64_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_base64
        ]
        self.suspicious_tags_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_tags
        ]
        self.whitelist_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.whitelist_patterns
        ]
        
        # Load configuration if exists
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            config = configparser.ConfigParser()
            config.read(self.config_file)
            
            if 'PHP_MONITOR' in config:
                section = config['PHP_MONITOR']
                if 'php_paths' in section:
                    self.php_paths = json.loads(section['php_paths'])
                if 'log_paths' in section:
                    self.log_paths = json.loads(section['log_paths'])
                if 'ftp_log' in section:
                    self.ftp_log = section['ftp_log']
                if 'recent_hours' in section:
                    self.recent_hours = int(section['recent_hours'])
                if 'max_file_size' in section:
                    self.max_file_size = int(section['max_file_size'])
                if 'db_check_enabled' in section:
                    self.db_check_enabled = section.getboolean('db_check_enabled')


class Logger:
    """Centralized logging management"""
    def __init__(self, config: Config):
        self.config = config
        self.log_dir = config.log_dir
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging system"""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"scan_{timestamp}.log"
        self.alert_file = self.log_dir / f"alerts_{timestamp}.log"
        self.report_file = self.log_dir / f"report_{timestamp}.txt"
        
        # Logging configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('php_monitor')
        
        # Alert handler
        alert_handler = logging.FileHandler(self.alert_file)
        alert_handler.setLevel(logging.WARNING)
        alert_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(alert_handler)
        
        # Report file
        self.report_file.touch()
        
    def log(self, message: str, level: str = "info", to_report: bool = False, console: bool = False):
        """Log a message"""
        if level == "alert":
            self.logger.warning(f"ALERT: {message}")
        elif level == "error":
            self.logger.error(message)
        else:
            self.logger.info(message)
            
        if to_report:
            with open(self.report_file, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {message}\n")
        
        if console:
            print(message)


class FileHashBaseline:
    """Gestion de la baseline de fichiers pour détection des modifications"""
    
    def __init__(self, baseline_file: Path):
        self.baseline_file = baseline_file
        self.baseline = self.load_baseline()
        
    def load_baseline(self) -> Dict:
        """Charger la baseline existante"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_baseline(self):
        """Sauvegarder la baseline"""
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)
    
    def get_file_signature(self, filepath: str) -> Dict:
        """Obtenir la signature d'un fichier"""
        try:
            stat = os.stat(filepath)
            file_hash = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
            
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'ctime': stat.st_ctime,
                'hash': file_hash.hexdigest(),
                'inode': stat.st_ino
            }
        except:
            return {}
    
    def check_file_changes(self, filepath: str) -> Tuple[bool, str]:
        """Vérifier les changements par rapport à la baseline"""
        rel_path = os.path.relpath(filepath, '/')
        
        current_sig = self.get_file_signature(filepath)
        if not current_sig:
            return False, "Cannot read file"
        
        if rel_path in self.baseline:
            old_sig = self.baseline[rel_path]
            
            if current_sig['hash'] != old_sig.get('hash'):
                return True, "Content modified"
            
            # Vérifier si le fichier a été "touché" (mtime modifié mais contenu identique)
            if current_sig['mtime'] != old_sig.get('mtime') and current_sig['size'] == old_sig.get('size'):
                return True, "File touched (mtime changed)"
                
            # Vérifier ctime (changement de propriétaire/permissions)
            if current_sig['ctime'] != old_sig.get('ctime'):
                return True, "Metadata changed (ctime)"
                
        return False, "No changes"
    
    def update_baseline(self, filepath: str):
        """Mettre à jour la baseline avec le fichier actuel"""
        rel_path = os.path.relpath(filepath, '/')
        self.baseline[rel_path] = self.get_file_signature(filepath)


class FileSystemScanner:
    """File system scanner avec baseline"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.baseline = FileHashBaseline(config.baseline_file)
        
    def check_permissions(self) -> int:
        """Check for dangerous permissions - VERSION CORRIGÉE"""
        self.logger.log("=== Checking permissions ===", "info", console=True)
        count = 0
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    # Skip some directories
                    if any(x in root for x in ['/vendor/', '/node_modules/', '/cache/', '/tmp/', '.git/']):
                        continue
                        
                    for file in files:
                        if file.endswith('.php'):
                            filepath = os.path.join(root, file)
                            try:
                                stat_info = os.stat(filepath)
                                mode = stat_info.st_mode
                                
                                # CORRECTION : Vérification des permissions
                                perm = mode & 0o777
                                
                                # Fichiers PHP avec permissions trop larges
                                if perm >= 0o766:  # 766, 767, 777
                                    owner = self.get_file_owner(filepath)
                                    self.logger.log(f"Dangerous permission {oct(perm)} on {filepath} (owner: {owner})", 
                                                   "alert", console=True)
                                    self.logger.log(f"PERMISSION: {filepath} - {oct(perm)} (owner: {owner})", 
                                                   "info", to_report=True)
                                    count += 1
                                
                                # Vérifier SUID/SGID sur fichiers PHP (très dangereux)
                                if mode & 0o4000 or mode & 0o2000:
                                    self.logger.log(f"SUID/SGID bit set on PHP file: {filepath}", 
                                                   "alert", console=True)
                                    self.logger.log(f"SUID_PHP: {filepath}", "info", to_report=True)
                                    count += 1
                                    
                            except (OSError, PermissionError):
                                continue
                    
                    # Directories with dangerous permissions
                    for dirname in dirs:
                        dirpath = os.path.join(root, dirname)
                        try:
                            stat_info = os.stat(dirpath)
                            perm = stat_info.st_mode & 0o777
                            
                            # Dossiers avec permissions 777
                            if perm == 0o777:
                                # Vérifier si c'est un dossier "upload" légitime
                                if 'upload' not in dirname.lower() and 'tmp' not in dirname.lower():
                                    self.logger.log(f"Directory with 777 permission: {dirpath}", 
                                                   "alert", console=True)
                                    self.logger.log(f"DIR_PERMISSION: {dirpath} - 777", "info", to_report=True)
                                    count += 1
                        except (OSError, PermissionError):
                            continue
            except Exception as e:
                self.logger.log(f"Error scanning {path}: {str(e)}", "error")
                
        self.logger.log(f"Permissions: {count} problems detected", "info")
        self.logger.log(f"=== Permission summary: {count} alerts ===", "info", to_report=True)
        return count
    
    def get_file_owner(self, filepath: str) -> str:
        """Get file owner"""
        try:
            import pwd
            stat_info = os.stat(filepath)
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except:
            return "unknown"
    
    def check_recent_files(self) -> int:
        """Check recently modified/created files - VERSION AMÉLIORÉE"""
        self.logger.log(f"=== Recently modified/created files ({self.config.recent_hours}h) ===", "info", console=True)
        count = 0
        recent_time = time.time() - (self.config.recent_hours * 3600)
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    # Skip some directories
                    if any(x in root for x in ['/vendor/', '/node_modules/', '/cache/', '/tmp/', '.git/']):
                        continue
                        
                    for file in files:
                        if file.endswith('.php'):
                            filepath = os.path.join(root, file)
                            try:
                                # CORRECTION : Vérifier mtime ET ctime
                                mtime = os.path.getmtime(filepath)
                                ctime = os.path.getctime(filepath)
                                
                                # Utiliser le plus récent des deux
                                last_change = max(mtime, ctime)
                                
                                if last_change > recent_time:
                                    size = os.path.getsize(filepath)
                                    size_kb = size // 1024
                                    mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                                    ctime_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                                    
                                    change_type = "modified" if mtime > recent_time else "created/owned changed"
                                    
                                    self.logger.log(f"Recent {change_type} file: {filepath}", 
                                                   "info", console=True)
                                    self.logger.log(f"       mtime: {mtime_str}, ctime: {ctime_str}, size: {size_kb}KB", 
                                                   "info")
                                    self.logger.log(f"RECENT_FILE: {filepath} - {change_type}", 
                                                   "info", to_report=True)
                                    self.logger.log(f"       mtime: {mtime_str}, ctime: {ctime_str}", 
                                                   "info", to_report=True)
                                    count += 1
                                    
                                    # Vérifier avec la baseline
                                    changed, reason = self.baseline.check_file_changes(filepath)
                                    if changed:
                                        self.logger.log(f"Baseline alert: {filepath} - {reason}", 
                                                       "alert", console=True)
                                        self.logger.log(f"BASELINE_ALERT: {filepath} - {reason}", 
                                                       "info", to_report=True)
                                    
                            except (OSError, PermissionError):
                                continue
            except Exception as e:
                self.logger.log(f"Error scanning {path}: {str(e)}", "error")
                
        self.logger.log(f"Recent files: {count} detected", "info")
        self.logger.log(f"=== Recent files summary: {count} files ===", "info", to_report=True)
        return count
    
    def check_suspicious_code(self) -> int:
        """Analyze suspicious PHP code avec whitelist"""
        self.logger.log("=== Analyzing suspicious code ===", "info", console=True)
        count = 0
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    if '/vendor/' in root or '/node_modules/' in root:
                        continue
                        
                    for file in files:
                        if file.endswith('.php'):
                            filepath = os.path.join(root, file)
                            
                            try:
                                # Check file size
                                if os.path.getsize(filepath) > self.config.max_file_size:
                                    continue
                                    
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                # Vérifier la whitelist d'abord
                                is_whitelisted = False
                                for whitelist_pattern in self.config.whitelist_regex:
                                    if whitelist_pattern.search(content):
                                        is_whitelisted = True
                                        self.logger.log(f"File whitelisted: {filepath}", "info")
                                        break
                                
                                if is_whitelisted:
                                    continue
                                    
                                # Rechercher fonctions suspectes avec contexte
                                suspicious_found = False
                                for i, line in enumerate(content.splitlines(), 1):
                                    # Skip comments
                                    stripped = line.strip()
                                    if stripped.startswith(('//', '#', '/*', '*', '*/')):
                                        continue
                                        
                                    # Rechercher patterns spécifiques (moins de faux positifs)
                                    for pattern in self.config.suspicious_functions_regex:
                                        if pattern.search(line):
                                            suspicious_found = True
                                            self.logger.log(f"Suspicious code in {filepath} line {i}", 
                                                           "alert", console=True)
                                            self.logger.log(f"       {line[:100].strip()}", "alert")
                                            self.logger.log(f"SUSPICIOUS_CODE: {filepath} - line {i}", 
                                                           "info", to_report=True)
                                            self.logger.log(f"       Pattern: {pattern.pattern}", 
                                                           "info", to_report=True)
                                            break
                                    
                                    # Rechercher obfuscation base64 spécifique
                                    for pattern in self.config.suspicious_base64_regex:
                                        if pattern.search(line):
                                            self.logger.log(f"Base64 obfuscation in {filepath} line {i}", 
                                                           "alert", console=True)
                                            self.logger.log(f"BASE64_OBFUSCATION: {filepath} - line {i}", 
                                                           "info", to_report=True)
                                            suspicious_found = True
                                
                                if suspicious_found:
                                    count += 1
                                    
                            except (IOError, UnicodeDecodeError, PermissionError):
                                continue
            except Exception as e:
                self.logger.log(f"Error scanning {path}: {str(e)}", "error")
                
        self.logger.log(f"Suspicious code: {count} files with malicious patterns", "info")
        self.logger.log(f"=== Suspicious code summary: {count} files ===", "info", to_report=True)
        return count
    
    def check_folder_consistency(self) -> int:
        """Check folder consistency - FOCUS SUR DOSSIERS SENSIBLES"""
        self.logger.log("=== Checking folder consistency ===", "info", console=True)
        count = 0
        
        # Seulement les dossiers vraiment sensibles
        sensitive_dirs = ["uploads", "upload", "images", "media", "cache", "tmp", "temp"]
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    # Vérifier si c'est un dossier sensible
                    dir_name = os.path.basename(root).lower()
                    if any(sens_dir in dir_name for sens_dir in sensitive_dirs):
                        if '/vendor/' in root or '/node_modules/' in root:
                            continue
                            
                        for file in files:
                            if file.endswith('.php'):
                                filepath = os.path.join(root, file)
                                
                                # Vérifier si c'est un fichier système légitime
                                if file in ['index.php', 'thumb.php']:
                                    continue
                                    
                                self.logger.log(f"PHP file in sensitive directory: {filepath}", 
                                               "alert", console=True)
                                self.logger.log(f"SENSITIVE_DIR_PHP: {filepath}", "info", to_report=True)
                                count += 1
                                
            except Exception as e:
                self.logger.log(f"Error scanning {path}: {str(e)}", "error")
                
        self.logger.log(f"Folder consistency: {count} PHP files in sensitive directories", "info")
        self.logger.log(f"=== Consistency summary: {count} alerts ===", "info", to_report=True)
        return count
    
    def check_injected_html(self) -> int:
        """Detect injected HTML content - VERSION CIBLÉE"""
        self.logger.log("=== Detecting injected HTML content ===", "info", console=True)
        count = 0
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    # CORRECTION : Seulement dans certains dossiers
                    if not any(x in root.lower() for x in ['uploads', 'cache', 'tmp', 'temp', 'media']):
                        continue
                        
                    if '/vendor/' in root or '/node_modules/' in root:
                        continue
                        
                    for file in files:
                        # Seulement certains types de fichiers
                        if file.endswith(('.txt', '.html', '.htm', '.js', '.css')):
                            filepath = os.path.join(root, file)
                            
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                # Vérifier si c'est un fichier minifié (ignorer)
                                if len(content) > 10000 and ';' in content and content.count('\n') < 10:
                                    continue
                                    
                                for pattern in self.config.suspicious_tags_regex:
                                    if pattern.search(content):
                                        self.logger.log(f"Suspicious HTML content in {filepath}", 
                                                       "alert", console=True)
                                        self.logger.log(f"INJECTED_HTML: {filepath}", "info", to_report=True)
                                        count += 1
                                        break
                                        
                            except (IOError, UnicodeDecodeError, PermissionError):
                                continue
            except Exception as e:
                self.logger.log(f"Error scanning {path}: {str(e)}", "error")
                
        self.logger.log(f"Injected HTML: {count} contaminated files", "info")
        self.logger.log(f"=== Injected HTML summary: {count} files ===", "info", to_report=True)
        return count
    
    def create_baseline(self):
        """Créer une baseline initiale des fichiers"""
        self.logger.log("=== Creating file baseline ===", "info", console=True)
        file_count = 0
        
        for path in self.config.php_paths:
            if not os.path.isdir(path):
                continue
                
            try:
                for root, dirs, files in os.walk(path):
                    # Skip some directories
                    if any(x in root for x in ['/vendor/', '/node_modules/', '/cache/', '/tmp/', '.git/']):
                        continue
                        
                    for file in files:
                        if file.endswith('.php'):
                            filepath = os.path.join(root, file)
                            try:
                                self.baseline.update_baseline(filepath)
                                file_count += 1
                            except:
                                pass
            except Exception as e:
                self.logger.log(f"Error creating baseline for {path}: {str(e)}", "error")
        
        self.baseline.save_baseline()
        self.logger.log(f"Baseline created for {file_count} files", "info", console=True)


class DatabaseScanner:
    """Database scanner - VERSION SÉCURISÉE"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.db_config = {}
        
        # Ne charger la config DB que si explicitement activé
        if config.db_check_enabled:
            self.load_db_config()
        else:
            self.logger.log("Database scanning is DISABLED by default for security", "info", console=True)
    
    def load_db_config(self):
        """Load database configuration"""
        db_config_file = Path("/etc/php_monitor/mysql.conf")
        if db_config_file.exists():
            try:
                config = configparser.ConfigParser()
                config.read(db_config_file)
                
                if 'DATABASE' in config:
                    self.db_config = dict(config['DATABASE'])
                    
                    # Vérifier que le mot de passe n'est pas vide
                    if not self.db_config.get('password'):
                        self.logger.log("WARNING: MySQL password is empty in config", "alert", console=True)
            except Exception as e:
                self.logger.log(f"Error loading DB config: {str(e)}", "error")
                self.db_config = {}
        else:
            self.logger.log("MySQL configuration file not found", "info")
    
    def check_db_malicious_content_safe(self):
        """Vérification sécurisée du contenu de la base de données"""
        if not self.db_config:
            self.logger.log("No database configuration available", "info")
            return
            
        self.logger.log("=== Safe database content analysis ===", "info", console=True)
        
        try:
            # 1. D'abord obtenir la liste des tables avec contenu texte
            tables_query = """
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME IN ('posts', 'pages', 'comments', 'options', 'settings', 'content')
            """
            
            result = self.execute_mysql_query_safe(tables_query)
            if not result:
                self.logger.log("No content tables found or access denied", "info")
                return
            
            tables = [line.strip() for line in result.strip().split('\n') if line.strip()]
            
            for table in tables:
                # 2. Obtenir les colonnes de type texte
                columns_query = f"""
                    SELECT COLUMN_NAME 
                    FROM information_schema.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = '{table}'
                    AND DATA_TYPE IN ('varchar', 'text', 'longtext', 'mediumtext')
                """
                
                columns_result = self.execute_mysql_query_safe(columns_query)
                if not columns_result:
                    continue
                    
                columns = [col.strip() for col in columns_result.strip().split('\n') if col.strip()]
                
                # 3. Pour chaque colonne, extraire un échantillon et analyser côté Python
                for column in columns:
                    # Extraire un échantillon limité
                    sample_query = f"SELECT `{column}` FROM `{table}` WHERE `{column}` IS NOT NULL LIMIT 100"
                    sample_result = self.execute_mysql_query_safe(sample_query)
                    
                    if sample_result:
                        self.analyze_db_content_sample(table, column, sample_result)
                        
        except Exception as e:
            self.logger.log(f"Error in safe DB analysis: {str(e)}", "error")
    
    def analyze_db_content_sample(self, table: str, column: str, sample: str):
        """Analyser un échantillon de contenu côté Python"""
        suspicious_patterns = [
            (r'<script[^>]*>.*eval\s*\(', "JavaScript eval in script tag"),
            (r'<iframe[^>]*src\s*=\s*[\'"](?!https?://)', "Suspicious iframe src"),
            (r'eval\s*\(\s*base64_decode', "eval with base64_decode"),
            (r'/\*.*\*/.*union.*select', "SQL injection pattern"),
        ]
        
        lines = sample.strip().split('\n')
        for i, line in enumerate(lines):
            if len(line) > 10000:  # Ignorer les très longs contenus
                continue
                
            for pattern, description in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.logger.log(f"Suspicious content in {table}.{column}, sample {i+1}: {description}", 
                                   "alert", console=True)
                    self.logger.log(f"DB_CONTENT_ALERT: {table}.{column} - {description}", 
                                   "info", to_report=True)
                    break
    
    def execute_mysql_query_safe(self, query: str) -> Optional[str]:
        """Exécuter une requête MySQL de manière sécurisée"""
        try:
            # Utiliser des variables d'environnement pour plus de sécurité
            env = os.environ.copy()
            
            cmd = [
                'mysql',
                '--batch',
                '--skip-column-names',
                '-h', self.db_config.get('host', 'localhost'),
                '-u', self.db_config.get('user', 'root'),
                '-D', self.db_config.get('database', 'mysql')
            ]
            
            # Ajouter le mot de passe via environnement ou fichier
            password = self.db_config.get('password', '')
            if password:
                env['MYSQL_PWD'] = password
            
            result = subprocess.run(
                cmd,
                input=query.encode(),
                capture_output=True,
                env=env,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.decode('utf-8', errors='ignore')
            else:
                error_msg = result.stderr.decode('utf-8', errors='ignore')[:200]
                if "access denied" in error_msg.lower():
                    self.logger.log(f"MySQL access denied for user {self.db_config.get('user')}", "error")
                return None
                
        except Exception as e:
            self.logger.log(f"MySQL execution error: {str(e)}", "error")
            return None


class LogAnalyzer:
    """Log analyzer avec décodage URL"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        
        # Patterns améliorés pour les attaques
        self.lfi_patterns = [
            r'\.\./',
            r'\.\.%2F',
            r'\.\.%252F',  # double encoding
            r'\.\.%c0%af',  # UTF-8 evasion
            r'php://filter',
            r'php://input',
            r'%00',  # null byte
            r'\.\.\\',  # Windows
        ]
        
        self.sql_patterns = [
            r'union.*select',
            r'select.*from',
            r'insert.*into',
            r'delete.*from',
            r'update.*set',
            r'drop.*table',
            r'--\s*$',
            r'/\*.*\*/',
            r'1=1',
            r'waitfor.*delay',
            r'benchmark\(',
        ]
        
        self.xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'alert\s*\(',
            r'document\.',
            r'window\.',
        ]
    
    def normalize_url(self, url: str) -> str:
        """Normaliser une URL (décodage multiple)"""
        try:
            # Décodage itératif
            normalized = url
            for _ in range(3):  # Maximum 3 niveaux d'encodage
                try:
                    decoded = urllib.parse.unquote(normalized)
                    if decoded == normalized:
                        break
                    normalized = decoded
                except:
                    break
            
            # Supprimer les caractères NULL
            normalized = normalized.replace('\x00', '')
            
            return normalized
        except:
            return url
    
    def check_web_logs(self):
        """Analyze web logs avec décodage"""
        self.logger.log("=== Analyzing web logs (with URL decoding) ===", "info", console=True)
        
        for log_path in self.config.log_paths:
            if not os.path.isdir(log_path):
                continue
                
            try:
                log_files = []
                for root, dirs, files in os.walk(log_path):
                    for file in files:
                        if file.endswith(('.log', '.access.log', '.error.log')):
                            log_files.append(os.path.join(root, file))
                
                for log_file in log_files[:3]:  # Limiter à 3 fichiers
                    self.analyze_log_file_enhanced(log_file)
            except Exception as e:
                self.logger.log(f"Error scanning logs {log_path}: {str(e)}", "error")
    
    def analyze_log_file_enhanced(self, log_file: str):
        """Analyze log file with enhanced detection"""
        self.logger.log(f"Analyzing: {log_file}", "info", console=True)
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-2000:]  # Dernières 2000 lignes
            
            attacks_detected = {
                'lfi': 0,
                'sql': 0,
                'xss': 0,
                'long_url': 0,
                'base64': 0,
            }
            
            for line in lines:
                # Extraire l'URL de la ligne de log (format commun)
                url_match = re.search(r'"GET\s+([^"]+)"|\s+/([^\s]+)\s+HTTP', line)
                if url_match:
                    url = url_match.group(1) or url_match.group(2) or ""
                    
                    # Normaliser l'URL
                    normalized_url = self.normalize_url(url)
                    
                    # Vérifier les patterns dans l'URL normalisée
                    self.detect_attacks_in_url(normalized_url, attacks_detected, line)
                
                # Vérifier aussi dans toute la ligne (pour POST data, etc.)
                self.detect_attacks_in_line(line, attacks_detected)
            
            # Afficher le résumé
            self.report_attacks(log_file, attacks_detected)
                    
        except (IOError, UnicodeDecodeError, PermissionError) as e:
            self.logger.log(f"Error analyzing {log_file}: {str(e)}", "error")
    
    def detect_attacks_in_url(self, url: str, attacks: Dict, log_line: str):
        """Détecter les attaques dans une URL"""
        # URLs anormalement longues
        if len(url) > 500:
            attacks['long_url'] += 1
            if attacks['long_url'] <= 3:  # Limiter les logs
                self.logger.log(f"Long URL detected ({len(url)} chars): {url[:100]}...", 
                               "alert", console=True)
                self.logger.log(f"LONG_URL: {log_line[:200]}", "info", to_report=True)
        
        # LFI/RFI attempts
        for pattern in self.lfi_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                attacks['lfi'] += 1
                if attacks['lfi'] <= 3:
                    self.logger.log(f"LFI/RFI attempt: {pattern} in URL", "alert", console=True)
                    break
        
        # SQL injection attempts
        for pattern in self.sql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                attacks['sql'] += 1
                if attacks['sql'] <= 3:
                    self.logger.log(f"SQL injection attempt: {pattern}", "alert", console=True)
                    break
        
        # XSS attempts
        for pattern in self.xss_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                attacks['xss'] += 1
                if attacks['xss'] <= 3:
                    self.logger.log(f"XSS attempt: {pattern}", "alert", console=True)
                    break
        
        # Base64 in parameters
        base64_pattern = r'[\?&](?:[A-Za-z0-9+/]{20,}={0,2}|%[0-9A-F]{2})'
        if re.search(base64_pattern, url, re.IGNORECASE):
            attacks['base64'] += 1
    
    def detect_attacks_in_line(self, line: str, attacks: Dict):
        """Détecter les attaques dans une ligne de log complète"""
        # Rechercher des patterns dans toute la ligne
        if any(pattern in line.lower() for pattern in ['/etc/passwd', '/etc/shadow', '/proc/']):
            attacks['lfi'] += 1
        
        if '<?php' in line and 'eval(' in line:
            attacks['xss'] += 1
    
    def report_attacks(self, log_file: str, attacks: Dict):
        """Afficher un résumé des attaques détectées"""
        total_attacks = sum(attacks.values())
        
        if total_attacks > 0:
            self.logger.log(f"Attack summary for {os.path.basename(log_file)}:", "info", console=True)
            for attack_type, count in attacks.items():
                if count > 0:
                    self.logger.log(f"  {attack_type.upper()}: {count} attempts", "info", console=True)
            
            # Ajouter au rapport
            self.logger.log(f"LOG_ATTACKS: {os.path.basename(log_file)} - {total_attacks} total attempts", 
                           "info", to_report=True)
            for attack_type, count in attacks.items():
                if count > 0:
                    self.logger.log(f"  {attack_type}: {count}", "info", to_report=True)
    
    def check_ftp_logs(self):
        """Analyze FTP logs"""
        ftp_log = Path(self.config.ftp_log)
        if not ftp_log.exists():
            return
            
        self.logger.log("=== Analyzing FTP logs ===", "info", console=True)
        
        try:
            with open(ftp_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-1000:]  # Dernières 1000 lignes
            
            php_uploads = []
            failed_logins = 0
            
            for line in lines:
                # PHP file uploads
                if '.php' in line.lower() and ('upload' in line.lower() or 'STOR' in line):
                    php_uploads.append(line.strip())
                
                # Failed logins
                if any(x in line.lower() for x in ['fail', 'failed', 'authentication failure']):
                    failed_logins += 1
            
            # Afficher les alertes
            if failed_logins > 10:
                self.logger.log(f"{failed_logins} failed FTP login attempts", "alert", console=True)
                self.logger.log(f"FTP_FAILED_LOGINS: {failed_logins} attempts", "info", to_report=True)
            
            for upload in php_uploads[-5:]:  # Derniers 5 uploads
                self.logger.log(f"FTP PHP file upload: {upload[:150]}", "alert", console=True)
                self.logger.log(f"FTP_PHP_UPLOAD: {upload[:200]}", "info", to_report=True)
                
        except (IOError, UnicodeDecodeError, PermissionError) as e:
            self.logger.log(f"Error analyzing FTP logs: {str(e)}", "error")


class PHPSeurityMonitor:
    """Main PHP Security Monitor class"""
    
    def __init__(self):
        self.config = Config()
        self.logger = Logger(self.config)
        self.fs_scanner = FileSystemScanner(self.config, self.logger)
        self.db_scanner = DatabaseScanner(self.config, self.logger)
        self.log_analyzer = LogAnalyzer(self.config, self.logger)
        
        # Create necessary directories
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self.config.snapshot_dir.mkdir(parents=True, exist_ok=True)
    
    def run_scan(self):
        """Run complete scan"""
        start_time = time.time()
        
        print("=" * 60)
        print("PHP SECURITY MONITOR v3.1 - ENHANCED EDITION")
        print("=" * 60)
        print(f"Start: {datetime.now():%Y-%m-%d %H:%M:%S}")
        print(f"Monitored paths: {', '.join(self.config.php_paths)}")
        print(f"Database scan: {'ENABLED' if self.config.db_check_enabled else 'DISABLED (secure by default)'}")
        print("=" * 60)
        print()
        
        alert_count = 0
        
        # Option: créer une baseline si elle n'existe pas
        if not self.config.baseline_file.exists():
            self.logger.log("No baseline found. Creating initial baseline...", "info", console=True)
            self.fs_scanner.create_baseline()
        
        # 1. PHP file monitoring
        alert_count += self.fs_scanner.check_permissions()
        alert_count += self.fs_scanner.check_recent_files()
        alert_count += self.fs_scanner.check_suspicious_code()
        alert_count += self.fs_scanner.check_folder_consistency()
        alert_count += self.fs_scanner.check_injected_html()
        
        # 2. Database monitoring (safe version)
        if self.config.db_check_enabled:
            self.db_scanner.check_db_malicious_content_safe()
        
        # 3. Log analysis with enhanced detection
        self.log_analyzer.check_web_logs()
        self.log_analyzer.check_ftp_logs()
        
        end_time = time.time()
        duration = int(end_time - start_time)
        
        # Final report
        print()
        print("=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)
        print(f"Duration: {duration} seconds")
        print(f"Log file: {self.logger.log_file}")
        print(f"Alert file: {self.logger.alert_file}")
        print(f"Report file: {self.logger.report_file}")
        
        if self.config.baseline_file.exists():
            print(f"Baseline file: {self.config.baseline_file}")
        print("=" * 60)
        print()
        
        # Count alerts in file
        try:
            with open(self.logger.alert_file, 'r', encoding='utf-8') as f:
                alert_file_count = f.read().count('ALERT:')
        except:
            alert_file_count = 0
        
        if alert_file_count > 0:
            print(f"⚠️  {alert_file_count} SECURITY ALERTS DETECTED!")
            print()
            
            # Show first 10 alerts with file names
            try:
                with open(self.logger.alert_file, 'r', encoding='utf-8') as f:
                    alert_lines = f.readlines()
                
                print("TOP ALERTS:")
                print("-" * 60)
                
                displayed = 0
                for line in alert_lines:
                    if 'ALERT:' in line:
                        # Extraire le nom du fichier si présent
                        if '.php' in line or '.html' in line or '.txt' in line:
                            # Trouver le chemin du fichier
                            for path in self.config.php_paths:
                                if path in line:
                                    # Afficher de manière lisible
                                    clean_line = line.strip()
                                    # Ajouter l'heure
                                    if ' - ALERT: ' in clean_line:
                                        parts = clean_line.split(' - ALERT: ', 1)
                                        print(f"{parts[0]} - {parts[1][:100]}")
                                    else:
                                        print(clean_line[:120])
                                    displayed += 1
                                    break
                        
                        if displayed >= 10:
                            break
                            
            except Exception as e:
                print(f"Error reading alert file: {str(e)}")
                
            print()
            print(f"⚠️  CHECK {self.logger.alert_file} FOR COMPLETE DETAILS")
            print("⚠️  RECOMMENDED: Review all alerts and take appropriate action")
            sys.exit(1)
        else:
            print("✅ NO SECURITY ALERTS DETECTED")
            print("✅ System appears to be clean")
            sys.exit(0)


def check_root():
    """Check if script is run as root"""
    if os.geteuid() != 0:
        print("ERROR: This script requires root permissions.")
        print(f"Usage: sudo {sys.argv[0]}")
        print()
        print("Required for:")
        print("  - Reading system files and logs")
        print("  - Checking file permissions")
        print("  - Accessing MySQL (if enabled)")
        sys.exit(1)


def main():
    """Main function"""
    check_root()
    
    try:
        monitor = PHPSeurityMonitor()
        monitor.run_scan()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()