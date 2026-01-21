# PHP SECURITY MONITOR v4.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-monitoring-red.svg)](#)

> **Surveillance de sécurité avancée pour les serveurs PHP**
> Détectez les webshells, les backdoors, les injections et les activités suspectes grâce à une analyse heuristique avancée.


## 🔍 Aperçu

**PHP Security Monitor v4.0** est un **outil de sécurité défensive** expert conçu pour les serveurs Linux hébergeant des applications PHP. Il utilise des heuristiques inspirées de l'IA pour détecter les **comportements malveillants, les mécanismes de persistance et les menaces complexes**.

Cet outil est particulièrement utile pour :

* Les environnements d'hébergement mutualisé
* Les serveurs VPS / Dédiés
* Les agences gérant plusieurs sites web PHP
* La réponse aux incidents et l'analyse forensique

### Menaces détectées

* Webshells et backdoors complexes
* Utilisation de fonctions PHP dangereuses (`eval`, `exec`, `shell_exec`, etc.)
* Obfuscation avancée et chaînes d'encodage
* Injections d'objets PHP et exploitation de wrappers
* Modifications de fichiers non autorisées via comparaison de ligne de base (SHA-256)


## ✨ Fonctionnalités clés

### 🔐 Sécurité du système de fichiers

* Analyse récursive et heuristique des fichiers PHP
* Gestion rigoureuse de la ligne de base (SHA-256)
* Détection de l'entropie élevée (potentielle obfuscation)
* Analyse des permissions et de l'appartenance

### 📜 Analyse des journaux

* Analyse intelligente des journaux Apache / Nginx
* Détection des modèles d'attaque et brute-force FTP

### 🗄 Surveillance de la base de données

* Analyse intelligente des tables SQL (colonnes de type texte/blob)
* Détection de payloads malveillants injectés via les mêmes règles heuristiques que les fichiers
* Support pour les bases de données MySQL/MariaDB

### 📊 Rapports et alertes

* Journaux structurés et rapports détaillés
* Niveaux de détection configurables (simple ou advanced)


## 🚀 Installation

### Prérequis

* Python **3.6+**
* Serveur Linux (Debian / Ubuntu / CentOS)
* Accès Root *(recommandé)*

### Installation rapide

```bash
sudo curl -o /usr/local/bin/php_monitoring.py \
  https://raw.githubusercontent.com/yourusername/php-security-monitor/main/php_monitoring.py

sudo chmod +x /usr/local/bin/php_monitoring.py

sudo mkdir -p \
  /etc/php_monitor_v4 \
  /var/log/php_monitor_v4 \
  /var/lib/php_monitor_v4/{snapshots,baseline}
```


## ⚙️ Configuration

### Fichier de configuration

Le script recherche son fichier de configuration dans `/etc/php_monitor_v4.conf`.

Exemple de contenu pour `php_monitor_v4.conf` :

```ini
[PHP_MONITOR]
detection_level = advanced
php_paths = ["/var/www/html", "/home/*/public_html"]
sensitive_dirs = ["uploads", "tmp", "cache", "temp"]
log_paths = ["/var/log/apache2", "/var/log/nginx"]
ftp_log = /var/log/vsftpd.log
recent_hours = 24
max_file_size = 10485760
db_check_enabled = true

[DATABASE]
enabled = true
host = localhost
user = php_monitor_ro
password = strong_password
database = your_database
target_tables = ["posts", "pages", "comments", "options"]
```

## 📖 Utilisation

### Initialisation (Ligne de base)

```bash
sudo php_monitoring.py
```

### Analyses régulières

```bash
sudo php_monitoring.py            # Analyse complète
sudo php_monitoring.py --verbose  # Sortie détaillée
sudo php_monitoring.py --help
```

Si vous rencontrez un problème d'encodage, exécuter cette commande : 

```bash
sudo iconv -f ISO-8859-1 -t UTF-8 php_monitor.py -o php_monitor_v4.py
```

## 📂 Structure du projet

```
/etc/php_monitor_v4.conf

/var/log/php_monitor_v4/
├── scan_YYYYMMDD_HHMMSS.log
└── report_YYYYMMDD_HHMMSS.txt

/var/lib/php_monitor_v4/
├── baseline.json
├── threats.json
└── snapshots/
```

## 📄 Licence

Licence MIT © 2024–2026 PHP Security Monitor Contributors

## ⚠️ Avertissement

Cet outil est fourni **uniquement à des fins de sécurité défensive**. Les auteurs déclinent toute responsabilité en cas de mauvaise utilisation ou de dommages résultant de son utilisation.

⭐ **Si ce projet vous aide, pensez à lui donner une étoile sur GitHub !**

*Dernière mise à jour : Janvier 2026 | Version 4.0.0*
