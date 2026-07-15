# PhishGuard

**Détection automatique de phishing — email, SMS & liens web, avec une spécialisation Mobile Money pour le Togo.**

PhishGuard analyse automatiquement les messages et liens reçus par un utilisateur — sans qu'il ait besoin de vérifier quoi que ce soit manuellement — pour détecter les tentatives de phishing (arnaques Mobile Money, faux colis, fausses offres d'emploi, fraude professionnelle, usurpation de grandes marques...).

🔗 **Démo en ligne :** [manuxx4.pythonanywhere.com](https://manuxx4.pythonanywhere.com)

Projet réalisé dans le cadre de la compétition **JPOPE 2026** (iP Net Institute of Technology, Lomé, Togo) — sélectionné au premier tour.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Stack technique](#stack-technique)
- [Installation locale](#installation-locale)
- [Configuration](#configuration)
- [Structure du projet](#structure-du-projet)
- [API](#api)
- [Clients (extension, mobile, Outlook)](#clients)
- [Tests](#tests)
- [Feuille de route](#feuille-de-route)

---

## Fonctionnalités

- **Analyse automatique en temps réel** — email (IMAP), SMS (app mobile), liens web (extension navigateur), pas un outil qu'on interroge manuellement
- **Moteur hybride explicable** — règles heuristiques + forensic de domaine (typosquatting, punycode, domaines à l'aspect généré aléatoirement) + machine learning (TF-IDF + Régression Logistique), avec justification systématique de chaque alerte
- **Détection de campagnes coordonnées** — corrèle plusieurs signalements pour identifier une attaque coordonnée plutôt qu'un message isolé, avec un seuil de confirmation à sources distinctes
- **Enrichissement optionnel** via VirusTotal (réputation ~70 antivirus) et URLScan.io (capture d'écran en direct), jamais dans le flux critique
- **Boucle d'amélioration continue** — correction manuelle des alertes, alimentant un futur ré-entraînement du modèle
- **Vérificateur de site** (`/check-url`) et **auto-diagnostic de sécurité** (`/security-checkup`) accessibles sans installation
- **Architecture manager/agent** — un moteur central, plusieurs clients légers (navigateur, mobile, email, Outlook), déployable pour un particulier comme pour une entreprise

## Architecture

```
Navigateur (extension)  ─┐
App Android              ─┤
Serveur mail (IMAP)      ─┼──►  MANAGER (Flask) ──► Règles + Forensic + ML ──► SQLite
Outlook (add-in)         ─┘         │
                                     └──► VirusTotal / URLScan.io (à la demande)
```

Un seul point d'entrée API (`/api/analyze`) reçoit du texte (message ou URL) et retourne un score de risque avec les raisons détaillées. Tous les clients l'interrogent de la même façon.

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Python, Flask, Flask-CORS |
| Machine learning | scikit-learn (TF-IDF + Régression Logistique), pandas |
| Base de données | SQLite |
| Extension navigateur | JavaScript (Manifest V3) |
| Application mobile | Flutter / Dart |
| Module Outlook | Office.js |
| Hébergement | PythonAnywhere |
| Threat intelligence | API VirusTotal, API URLScan.io |

## Installation locale

Prérequis : Python 3.10+

```bash
# 1. Cloner le dépôt
git clone https://github.com/Emmaxxx-04/phishguard-server.git
cd phishguard-server

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer les variables d'environnement (voir section Configuration)
cp .env.example .env

# 4. Entraîner le modèle (génère model.pkl à partir de data/dataset.csv)
python train_model.py

# 5. Lancer le serveur
python app.py
```

Le dashboard est accessible sur `http://localhost:5000`.

## Configuration

Toutes les clés sensibles se configurent via un fichier `.env` à la racine (jamais en dur dans le code) :

```env
# Surveillance email automatique (optionnel)
IMAP_HOST=imap.gmail.com
IMAP_USER=ton.email.test@gmail.com
IMAP_PASSWORD=xxxx-xxxx-xxxx-xxxx
IMAP_POLL_SECONDS=15

# Enrichissement Threat Intelligence (optionnel)
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
```

- Clé VirusTotal gratuite : https://www.virustotal.com/gui/join-us
- Clé URLScan.io gratuite : https://urlscan.io/user/signup

Sans ces clés, l'application fonctionne normalement — l'enrichissement externe affiche simplement un message "non configuré" au lieu de planter.

## Structure du projet

```
phishguard-server/
├── app.py                 # serveur Flask, routes, base de données
├── analyzer.py             # moteur de scoring (règles + ML)
├── urlintel.py              # forensic URL/domaine (typosquatting, domaines aléatoires...)
├── threat_intel.py          # intégrations VirusTotal / URLScan.io
├── train_model.py           # entraînement du modèle ML
├── data/
│   └── dataset.csv          # jeu de données d'entraînement
├── templates/
│   ├── dashboard.html        # tableau de bord principal
│   ├── check_url.html         # vérificateur de site
│   └── security_checkup.html  # auto-diagnostic de sécurité
├── model.pkl                 # modèle ML entraîné
├── requirements.txt
├── Procfile                  # commande de lancement en production
└── runtime.txt                # version Python
```

## API

| Endpoint | Méthode | Description |
|---|---|---|
| `/api/analyze` | POST | Point d'entrée principal — reçoit `{text, channel, sender}`, retourne le score et les raisons |
| `/api/feed` | GET | Historique des analyses, paginé et filtrable (`limit`, `offset`, `channel`, `date`) |
| `/api/stats` | GET | Statistiques globales |
| `/api/campaigns` | GET | Campagnes de phishing coordonnées détectées |
| `/api/feedback` | POST | Correction manuelle d'une analyse |
| `/api/threat-intel` | POST | Enrichissement VirusTotal à la demande |
| `/api/urlscan` | POST | Enrichissement URLScan.io à la demande |

## Clients

- **Extension Chrome/Edge** — scan automatique de Gmail + blocage de lien sur tous les sites
- **Application Android** (Flutter) — écoute les SMS entrants
- **Module Outlook** (Office.js) — construit et testé côté serveur ; installation dépendante des droits admin du tenant Microsoft 365
- **Poller IMAP** — intégré au serveur, surveille une boîte mail automatiquement

Le code de ces clients se trouve dans des dossiers séparés du projet complet (non inclus dans ce dépôt serveur).

## Tests

Le moteur est testé systématiquement à chaque modification :

```bash
python -c "
from analyzer import PhishingAnalyzer
a = PhishingAnalyzer()
r = a.analyze('Cher client, votre compte TMoney sera suspendu: http://tmoney-secure-verif.com', channel='test')
print(r['label'], r['score'])
"
```

Le jeu de données (`data/dataset.csv`) sert aussi de suite de non-régression : chaque exemple doit être correctement classé après toute modification du moteur.

## Feuille de route

- Vue "entreprise" — regrouper les alertes de plusieurs employés sur un même tableau de bord
- Threat Graph — visualisation des campagnes et infrastructures liées
- Élargissement du corpus d'entraînement avec des signalements réels
- Intégration Outlook validée en environnement sans restriction administrative

---

**Équipe PhishGuard** — JPOPE 2026
