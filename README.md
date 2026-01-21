# PHP SECURITY MONITOR v3.1

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-monitoring-red.svg)](#)

> **Surveillance de sécurité avancée pour les serveurs PHP**
> Détectez les webshells, les backdoors, les injections et les activités suspectes avant que les attaquants ne causent de réels dommages.

---

## 🔍 Aperçu

**PHP Security Monitor v3.1** est un **outil de sécurité défensive** avancé conçu pour les serveurs Linux hébergeant des applications PHP. Il analyse en continu les fichiers, les journaux, les configurations et (en option) les bases de données pour détecter les **comportements malveillants, les mécanismes de persistance et les pratiques de sécurité fragiles**.

Cet outil est particulièrement utile pour :

* Les environnements d'hébergement mutualisé
* Les serveurs VPS / Dédiés
* Les agences gérant plusieurs sites web PHP
* La réponse aux incidents et l'analyse forensique

### Menaces détectées

* Webshells et backdoors
* Utilisation de fonctions PHP dangereuses (`eval`, `exec`, `shell_exec`, etc.)
* Modifications de fichiers non autorisées
* Permissions suspectes (777, SUID)
* Tentatives d'attaque basées sur les journaux
* Injection de contenu dans la base de données *(optionnel)*

---

## ✨ Fonctionnalités clés

### 🔐 Sécurité du système de fichiers

* Analyse récursive des fichiers PHP
* Vérification de l'intégrité et de la ligne de base (SHA-256)
* Détection des fichiers récemment modifiés
* Analyse des permissions et de l'appartenance
* Inspection de code heuristique

### 📜 Analyse des journaux

* Analyse des journaux Apache / Nginx
* Détection des modèles d'attaque courants
* Brute-force FTP et téléchargements suspects

### 🛠 Audit de configuration

* Validation des directives de sécurité PHP
* Détection de configurations risquées

### 🗄 Surveillance de la base de données *(Optionnel)*

* Analyser des tables spécifiques pour les charges utiles injectées
* Comparaison basée sur des instantanés
* Accès DB en lecture seule recommandé

### 📊 Rapports et alertes

* Journaux structurés
* Journaux d'alertes uniquement
* Rapports lisibles par l'homme
* Exécution compatible avec Cron

---

## 🚀 Installation

### Prérequis

* Python **3.6+**
* Serveur Linux (Debian / Ubuntu / CentOS testés)
* Accès Root *(recommandé)*

### Installation rapide

```bash
sudo curl -o /usr/local/bin/php_monitor.py \
  https://raw.githubusercontent.com/yourusername/php-security-monitor/main/php_monitor.py

sudo chmod +x /usr/local/bin/php_monitor.py

sudo mkdir -p \
  /etc/php_monitor \
  /var/log/php_monitor \
  /var/lib/php_monitor/{snapshots,baseline}
```

### Installation depuis les sources

```bash
git clone https://github.com/yourusername/php-security-monitor.git
cd php-security-monitor

sudo pip3 install -r requirements.txt  # Optionnel
sudo cp php_monitor.py /usr/local/bin/
sudo chmod +x /usr/local/bin/php_monitor.py
```

---

## ⚙️ Configuration

### Configuration minimale

Créez `/etc/php_monitor.conf` :

```ini
[PHP_MONITOR]
php_paths = ["/var/www/html", "/home/*/public_html"]
log_paths = ["/var/log/apache2", "/var/log/nginx"]
ftp_log = /var/log/vsftpd.log
recent_hours = 24
max_file_size = 10485760

db_check_enabled = false
```

### Configuration avancée

```ini
[PHP_MONITOR]
php_paths = ["/var/www/html", "/home/*/www", "/opt/webapps"]
log_paths = ["/var/log/apache2", "/var/log/nginx", "/var/log/httpd"]
ftp_log = /var/log/vsftpd.log
recent_hours = 48
max_file_size = 5242880
alert_threshold = 5

[WHITELIST]
ignore_dirs = ["/vendor/", "/node_modules/", "/cache/", "/tmp/"]
ignore_patterns = ["Framework::", "LegacyCode::"]
```

### Analyse de la base de données (Optionnel)

```ini
[DATABASE]
host = localhost
user = php_monitor_ro
password = strong_password
database = your_database

target_tables = ["posts", "pages", "comments", "options"]
```

> ⚠️ **Conseil de sécurité** : Utilisez toujours un **utilisateur de base de données en lecture seule**.

---

## 📖 Utilisation

### Premier lancement (Création de la ligne de base)

```bash
sudo php_monitor.py
```

### Analyses régulières

```bash
sudo php_monitor.py            # Analyse complète
sudo php_monitor.py --verbose  # Sortie détaillée
sudo php_monitor.py --no-baseline
sudo php_monitor.py --help
```

### Intégration Cron

```bash
0 2 * * * /usr/bin/python3 /usr/local/bin/php_monitor.py

0 2 * * * /usr/bin/python3 /usr/local/bin/php_monitor.py | \
  mail -s "Rapport d'analyse de sécurité PHP" admin@example.com
```

---

## 📂 Structure du projet

```
/etc/php_monitor.conf

/var/log/php_monitor/
├── scan_YYYYMMDD_HHMMSS.log
├── alerts_YYYYMMDD_HHMMSS.log
└── report_YYYYMMDD_HHMMSS.txt

/var/lib/php_monitor/
├── baseline.json
├── snapshots/
└── baseline/
```

---

## 🔐 Bonnes pratiques de sécurité

* Exécuter en tant que **root** uniquement si nécessaire
* Examiner les alertes régulièrement
* Effectuer une rotation des journaux avec `logrotate`
* Garder le script à jour
* Traiter les alertes comme des indicateurs, pas comme une vérité absolue

---

## 🤝 Contribution

Les contributions sont les bienvenues !

```bash
git checkout -b feature/nouvelle-fonctionnalite
git commit -m "Ajout d'une nouvelle règle de détection"
git push origin feature/nouvelle-fonctionnalite
```

---

## 📄 Licence

Licence MIT © 2024–2026 PHP Security Monitor Contributors

---

## ⚠️ Avertissement

Cet outil est fourni **uniquement à des fins de sécurité défensive et de surveillance**. Les auteurs déclinent toute responsabilité en cas de mauvaise utilisation ou de dommages résultant d'une configuration ou d'une utilisation inappropriée.

---

⭐ **Si ce projet vous aide, pensez à lui donner une étoile sur GitHub !**

*Dernière mise à jour : Janvier 2026 | Version 3.1.0*
