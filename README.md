# PHP SECURITY MONITOR v3.1

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-monitoring-red.svg)](https://github.com/yourusername/php-security-monitor)

Un outil avancé de surveillance de sécurité pour serveurs PHP, conçu pour détecter les comportements malveillants et les vulnérabilités en temps réel.

## 📋 Table des matières

- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Alertes détectées](#alertes-détectées)
- [Structure du projet](#structure-du-projet)
- [Contribuer](#contribuer)
- [Sécurité](#sécurité)
- [License](#license)

## 🔍 Aperçu

**PHP SECURITY MONITOR v3.1** est une solution open-source complète pour la surveillance de sécurité des serveurs PHP. Face à la recrudescence des attaques (webshells, injections, backdoors), cet outil permet une détection proactive des menaces au niveau :

- 🗂️ **Système de fichiers** : Permissions, modifications suspectes, code malveillant
- 🗄️ **Base de données** : Contenu injecté, comptes compromis
- 📊 **Logs serveur** : Tentatives d'attaque, comportements anormaux
- 🔐 **Configuration** : Paramètres de sécurité, vulnérabilités connues

## ✨ Fonctionnalités

### 🛡️ **Surveillance système de fichiers**
- ✅ Détection des permissions dangereuses (777, SUID/SGID sur fichiers PHP)
- ✅ Surveillance des fichiers modifiés/récemment créés (mtime + ctime)
- ✅ Analyse de code PHP malveillant avec contexte
- ✅ Détection d'obfuscation Base64 avancée
- ✅ Whitelist intégrée pour éviter les faux positifs
- ✅ Système de baseline avec hash SHA256

### 🗄️ **Analyse base de données** *(optionnel)*
- ⚠️ Sécurisé par défaut (désactivé)
- ✅ User lecture seule recommandé
- ✅ Analyse côté Python (pas de requêtes dangereuses)
- ✅ Détection de contenu injecté dans les tables sensibles

### 📋 **Analyse logs serveur**
- ✅ Décodage URL multi-niveaux (UTF-8, double encoding)
- ✅ Détection LFI/RFI avec patterns étendus
- ✅ Identification tentatives SQL injection
- ✅ Analyse XSS dans les requêtes
- ✅ Surveillance logs FTP (upload PHP, échecs connexion)

### 📊 **Rapports avancés**
- ✅ Classification des alertes par sévérité
- ✅ Noms de fichiers clairement identifiés
- ✅ Statistiques par type d'attaque
- ✅ Export JSON/texte pour intégration SIEM

## 🚀 Installation

### Prérequis
- Python 3.6 ou supérieur
- Accès root (pour lecture fichiers système)
- Serveur Linux (testé sur Debian/Ubuntu/CentOS)

### Installation rapide

```bash
# 1. Télécharger le script
sudo curl -o /usr/local/bin/php_monitor.py \
  https://raw.githubusercontent.com/yourusername/php-security-monitor/main/php_monitor.py

# 2. Rendre exécutable
sudo chmod +x /usr/local/bin/php_monitor.py

# 3. Créer la structure de répertoires
sudo mkdir -p /etc/php_monitor \
  /var/log/php_monitor \
  /var/lib/php_monitor/{snapshots,baseline}
```

### Installation depuis le code source

```bash
git clone https://github.com/yourusername/php-security-monitor.git
cd php-security-monitor
sudo pip3 install -r requirements.txt  # Si dépendances futures
sudo cp php_monitor.py /usr/local/bin/
sudo chmod +x /usr/local/bin/php_monitor.py
```

## ⚙️ Configuration

### Configuration minimale

Créer `/etc/php_monitor.conf` :

```ini
[PHP_MONITOR]
# Chemins à surveiller (format JSON)
php_paths = ["/var/www/html", "/home/*/public_html"]

# Chemins des logs web
log_paths = ["/var/log/apache2", "/var/log/nginx"]

# Log FTP (optionnel)
ftp_log = /var/log/vsftpd.log

# Paramètres de scan
recent_hours = 24
max_file_size = 10485760  # 10MB

# IMPORTANT: Scan base de données désactivé par défaut
db_check_enabled = false
```

### Configuration avancée

```ini
[PHP_MONITOR]
php_paths = ["/var/www/html", "/home/*/www", "/opt/webapps"]
log_paths = ["/var/log/apache2", "/var/log/nginx", "/var/log/httpd"]
ftp_log = /var/log/vsftpd.log
recent_hours = 48
max_file_size = 5242880  # 5MB
alert_threshold = 5  # Nombre min d'alertes pour notification

[WHITELIST]
# Ignorer ces dossiers
ignore_dirs = ["/vendor/", "/node_modules/", "/cache/", "/tmp/"]
# Ignorer ces patterns dans le code
ignore_patterns = ["Framework::", "LegacyCode::"]
```

### Configuration base de données *(optionnel)*

```ini
[DATABASE]
host = localhost
user = php_monitor_ro  # Utiliser un compte lecture seule
password = votre_mot_de_passe_securise
database = votre_base

# Tables spécifiques à scanner
target_tables = ["posts", "pages", "comments", "options"]
```

## 📖 Utilisation

### Premier scan (création baseline)

```bash
sudo python3 /usr/local/bin/php_monitor.py
```

Le script créera automatiquement une baseline des fichiers PHP.

### Scans réguliers

```bash
# Scan complet
sudo php_monitor.py

# Scan avec sortie verbeuse
sudo php_monitor.py --verbose

# Scan sans vérification baseline
sudo php_monitor.py --no-baseline

# Afficher l'aide
sudo php_monitor.py --help
```

### Intégration avec cron

Pour une surveillance automatique quotidienne :

```bash
# Éditer crontab
sudo crontab -e

# Ajouter (exécution à 2h du matin)
0 2 * * * /usr/bin/python3 /usr/local/bin/php_monitor.py

# Avec envoi d'email en cas d'alertes
0 2 * * * /usr/bin/python3 /usr/local/bin/php_monitor.py | \
  mail -s "PHP Security Scan Report" admin@example.com
```

### Exemple de sortie

```
====================================================
PHP SECURITY MONITOR v3.1 - ENHANCED EDITION
====================================================
Start: 2024-01-15 14:30:00
Monitored paths: /var/www/html, /home/*/public_html
Database scan: DISABLED (secure by default)
====================================================

=== Checking permissions ===
ALERT: Dangerous permission 777 on /var/www/html/uploads/config.php
ALERT: SUID bit set on PHP file: /var/www/html/admin/tool.php

=== Recently modified files (24h) ===
Recent modified file: /var/www/html/new_shell.php
       mtime: 2024-01-15 02:15:00, ctime: 2024-01-15 02:15:00

=== Analyzing suspicious code ===
ALERT: Suspicious code in /var/www/html/new_shell.php line 15
       eval($_GET['cmd']);

====================================================
SCAN COMPLETE
====================================================
Duration: 45 seconds
Log file: /var/log/php_monitor/scan_20240115_143000.log
Alert file: /var/log/php_monitor/alerts_20240115_143000.log
Report file: /var/log/php_monitor/report_20240115_143000.txt
====================================================

⚠️  3 SECURITY ALERTS DETECTED!

TOP ALERTS:
----------------------------------------------------
2024-01-15 14:30:05 - /var/www/html/uploads/config.php (permission 777)
2024-01-15 14:30:10 - /var/www/html/admin/tool.php (SUID bit)
2024-01-15 14:30:15 - /var/www/html/new_shell.php (eval($_GET))

⚠️  CHECK /var/log/php_monitor/alerts_20240115_143000.log FOR DETAILS
⚠️  RECOMMENDED: Review all alerts and take appropriate action
```

## 📁 Structure du projet

```
/etc/
└── php_monitor.conf              # Configuration principale

/var/log/php_monitor/
├── scan_YYYYMMDD_HHMMSS.log      # Logs détaillés du scan
├── alerts_YYYYMMDD_HHMMSS.log    # Alertes uniquement
└── report_YYYYMMDD_HHMMSS.txt    # Rapport formaté

/var/lib/php_monitor/
├── baseline.json                 # Baseline des fichiers (hash SHA256)
├── snapshots/                    # Snapshots historiques
│   ├── db_admins_YYYYMMDD.snapshot
│   └── db_metrics_YYYYMMDD.snapshot
└── baseline/                     # Anciennes baselines (rotation)
```

Les contributions sont les bienvenues ! Voici comment participer :

1. **Fork** le projet
2. **Clone** votre fork
3. Créez une **branche** pour votre fonctionnalité
4. **Commit** vos changements
5. **Push** vers votre fork
6. Ouvrez une **Pull Request**

### Guide de contribution

```bash
# 1. Fork et clone
git clone https://github.com/votre-utilisateur/php-security-monitor.git
cd php-security-monitor

# 2. Créer une branche
git checkout -b feature/nouvelle-fonctionnalite

# 3. Installer pour développement
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt  # Si disponible

# 4. Tester vos modifications
python -m pytest tests/
sudo python3 php_monitor.py --test

# 5. Commit et push
git commit -m "Ajout: Nouvelle fonctionnalité"
git push origin feature/nouvelle-fonctionnalite
```

## 🔐 Sécurité

### Bonnes pratiques recommandées

1. **Exécuter en root uniquement** : Nécessaire pour la lecture système
2. **User DB lecture seule** : Pour le scan base de données
3. **Rotation des logs** : Configurer logrotate
4. **Revue régulière des alertes** : Analyser les faux positifs
5. **Mises à jour** : Maintenir le script à jour

### Sécurité du script
- ✅ Pas de dépendances externes non vérifiées
- ✅ Validation des entrées de configuration
- ✅ Échappement SQL côté Python
- ✅ Pas d'exécution de code non vérifié
- ✅ Logs sécurisés (permissions 600)

## 📄 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

```
MIT License

Copyright (c) 2024 PHP Security Monitor Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 🙏 Remerciements

- À tous les contributeurs open-source
- À la communauté de sécurité PHP
- Aux testeurs et rapporteurs de bugs


**⚠️ DISCLAIMER** : Cet outil est fourni à titre informatif. Les administrateurs système sont responsables de la configuration et de l'utilisation appropriée. L'auteur ne peut être tenu responsable des dommages causés par une mauvaise utilisation.

**⭐ Si ce projet vous est utile, pensez à lui donner une étoile sur GitHub !**

---

*Dernière mise à jour : Janvier 2026 | Version : 3.1.0*