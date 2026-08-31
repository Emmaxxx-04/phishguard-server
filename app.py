"""
PhishGuard Togo - Detection automatique de phishing (email + SMS/autres canaux)
Lancement: python3 app.py
"""
import os
import re
import threading
import contextlib
import time
import secrets
import base64
import hashlib
import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

from analyzer import PhishingAnalyzer
from urlintel import analyze_urls, is_allowlisted_domain
from threat_intel import check_virustotal, check_urlscan, check_virustotal_file
from pypdf import PdfReader
from oletools.olevba import VBA_Parser
from LnkParse3 import lnk_file
import zipfile
import tarfile
import py7zr
import io

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = Flask(__name__)
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "X-API-Key"])  # autorise l'extension Chrome (chrome-extension://...) a appeler l'API locale, y compris l'en-tete X-API-Key
# Cle de signature des sessions (cookie de connexion). A definir en variable
# d'environnement en production (SECRET_KEY) - sinon valeur de secours pour le dev local.
_SECRET = os.getenv("SECRET_KEY", "dev-secret-key-a-changer-en-production")
app.secret_key = _SECRET
analyzer = PhishingAnalyzer()

# Cle de chiffrement des mots de passe IMAP stockes en base, derivee de SECRET_KEY
# (jamais stockee en clair). Changer SECRET_KEY en production rendrait les
# connexions boite mail existantes illisibles - il faudrait alors les reconnecter.
_FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(_SECRET.encode()).digest()))

def encrypt_secret(plain):
    return _FERNET.encrypt(plain.encode()).decode()

def decrypt_secret(token):
    try:
        return _FERNET.decrypt(token.encode()).decode()
    except InvalidToken:
        return None


# =============================================================================
# Envoi d'emails (verification de compte, changement d'email, mot de passe
# oublie) via un compte Gmail dedie, configure par variables d'environnement -
# meme principe que la boite IMAP surveillee, mais en sortie cette fois.
# =============================================================================
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_NAME = "FishGuard"
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://fishguard.me")


_LAST_EMAIL_ATTEMPT = {"note": "aucune tentative recue depuis le dernier redemarrage du serveur"}


def send_email(to_addr, subject, body_text):
    """Envoie un email simple en texte brut. Retourne True si l'envoi a
    reussi, False sinon (jamais d'exception qui remonterait jusqu'a
    l'utilisateur - une panne d'envoi ne doit pas casser le reste du site)."""
    global _LAST_EMAIL_ATTEMPT
    if not (SMTP_USER and SMTP_PASSWORD):
        print("[EMAIL] SMTP_USER/SMTP_PASSWORD non configures - email non envoye.")
        _LAST_EMAIL_ATTEMPT = {
            "moment": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "destinataire": to_addr,
            "resultat": "ECHEC - SMTP_USER/SMTP_PASSWORD non configures sur ce service",
        }
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body_text, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
        msg["To"] = to_addr

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [to_addr], msg.as_string())
        _LAST_EMAIL_ATTEMPT = {
            "moment": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "destinataire": to_addr,
            "smtp_user_utilise": SMTP_USER,
            "smtp_host": SMTP_HOST,
            "resultat": "SUCCES - email envoye sans erreur",
        }
        return True
    except Exception as e:
        print(f"[EMAIL] Echec d'envoi vers {to_addr}: {e}")
        _LAST_EMAIL_ATTEMPT = {
            "moment": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "destinataire": to_addr,
            "smtp_user_utilise": SMTP_USER,
            "smtp_host": SMTP_HOST,
            "resultat": f"ECHEC - {type(e).__name__}: {e}",
        }
        return False


@app.route("/debug/last-email")
def debug_last_email():
    """Page de diagnostic temporaire : affiche la derniere tentative d'envoi
    d'email (succes ou erreur exacte), sans avoir besoin des logs Render.
    A retirer une fois le bug resolu."""
    return jsonify(_LAST_EMAIL_ATTEMPT)


def create_email_token(user_id, purpose, hours_valid=24):
    """Cree un jeton a usage unique (verification d'email ou reinitialisation
    de mot de passe), valable un temps limite."""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=hours_valid)).strftime("%Y-%m-%d %H:%M:%S")
    with DB_LOCK:
        conn = get_db()
        conn.execute(
            "INSERT INTO email_tokens (user_id, token, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, token, purpose, expires_at, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    return token


def consume_email_token(token, purpose):
    """Verifie qu'un jeton est valide (bon usage prevu, non expire, non deja
    utilise) et le marque comme consomme. Retourne le user_id si valide,
    sinon None. Chaque jeton ne peut servir qu'une seule fois."""
    with DB_LOCK:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM email_tokens WHERE token = ? AND purpose = ?",
            (token, purpose)
        ).fetchone()
        if not row:
            conn.close()
            return None
        if row["used_at"] is not None:
            conn.close()
            return None
        if datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now():
            conn.close()
            return None
        conn.execute(
            "UPDATE email_tokens SET used_at = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row["id"])
        )
        conn.commit()
        conn.close()
        return row["user_id"]


def send_verification_email(user_id, email_addr):
    """Ne doit jamais faire planter l'appelant (inscription, changement
    d'email) : toute erreur ici est loggee et avalee, l'email est simplement
    considere comme non envoye."""
    global _LAST_EMAIL_ATTEMPT
    try:
        token = create_email_token(user_id, "verify", hours_valid=48)
        link = f"{APP_BASE_URL}/verify-email/{token}"
        body = (
            "Bonjour,\n\n"
            "Merci de vous être inscrit sur FishGuard.\n"
            "Confirmez votre adresse email en cliquant sur ce lien (valable 48h) :\n\n"
            f"{link}\n\n"
            "Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.\n\n"
            "— L'équipe FishGuard"
        )
        return send_email(email_addr, "Confirmez votre adresse email — FishGuard", body)
    except Exception as e:
        print(f"[EMAIL] send_verification_email a echoue pour {email_addr}: {e}")
        _LAST_EMAIL_ATTEMPT = {
            "moment": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "destinataire": email_addr,
            "resultat": f"ECHEC AVANT send_email() - {type(e).__name__}: {e}",
        }
        return False


def send_password_reset_email(user_id, email_addr):
    """Meme principe : ne doit jamais faire planter l'appelant."""
    try:
        token = create_email_token(user_id, "reset", hours_valid=1)
        link = f"{APP_BASE_URL}/reset-password/{token}"
        body = (
            "Bonjour,\n\n"
            "Vous avez demandé à réinitialiser votre mot de passe FishGuard.\n"
            "Ce lien est valable 1 heure :\n\n"
            f"{link}\n\n"
            "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email — "
            "votre mot de passe actuel reste inchangé.\n\n"
            "— L'équipe FishGuard"
        )
        return send_email(email_addr, "Réinitialisation de votre mot de passe — FishGuard", body)
    except Exception as e:
        print(f"[EMAIL] send_password_reset_email a echoue pour {email_addr}: {e}")
        return False


def send_contact_message(name, from_email, subject, message_body):
    """Envoie un message du formulaire "Nous contacter" a l'adresse de
    l'equipe (SMTP_USER), avec Reply-To positionne sur l'adresse de la
    personne pour pouvoir lui repondre directement depuis n'importe quelle
    messagerie. Toujours appele dans un thread separe (voir route /contact) -
    ne doit jamais bloquer la requete HTTP le temps que le SMTP reponde."""
    if not (SMTP_USER and SMTP_PASSWORD):
        print("[EMAIL] SMTP_USER/SMTP_PASSWORD non configures - message de contact non envoye.")
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        body = f"De : {name} <{from_email}>\n\n{message_body}"
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"[FishGuard - Nous contacter] {subject}"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
        msg["To"] = SMTP_USER
        msg["Reply-To"] = from_email

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [SMTP_USER], msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL] Echec d'envoi du message de contact de {from_email}: {e}")
        return False


# =============================================================================
# Couche base de donnees : Postgres (Neon), avec une petite compatibilite qui
# garde la meme facon d'ecrire le code partout ailleurs dans ce fichier
# (conn.execute(...) -> objet avec .fetchone()/.fetchall(), acces aux colonnes
# par nom via row["colonne"], .lastrowid apres un INSERT ... RETURNING id).
# Auparavant sur SQLite (fichier local) : perdait toutes les donnees a chaque
# redemarrage/redeploiement sur l'hebergement gratuit -> Postgres externe
# (Neon, gratuit et persistant) regle definitivement ce probleme.
# =============================================================================
DATABASE_URL = os.environ.get("DATABASE_URL")

# Nombre minimum de comptes DISTINCTS devant signaler independamment un
# expediteur comme frauduleux avant que la correction manuelle d'un seul
# devienne "verite partagee" affectant les analyses des autres utilisateurs.
# Empeche un compte isole (erreur ou malveillance) de fausser la reputation
# partagee - voir api_feedback() et get_sender_reputation().
COMMUNITY_CONFIRM_THRESHOLD = 3

# --- DIAGNOSTIC TEMPORAIRE : affiche l'hote/base reellement utilises au ---
# --- demarrage, sans jamais logger le mot de passe. A retirer une fois ---
# --- le probleme de perte de donnees resolu. ---
if DATABASE_URL:
    try:
        _no_scheme = DATABASE_URL.split("://", 1)[1]
        _creds_and_rest = _no_scheme.split("@", 1)
        _user_part = _creds_and_rest[0].split(":")[0]
        _host_and_db = _creds_and_rest[1] if len(_creds_and_rest) > 1 else "?"
        print(f"[DB DIAGNOSTIC] Connexion utilisee -> user={_user_part} host_db={_host_and_db}", flush=True)
    except Exception as _e:
        print(f"[DB DIAGNOSTIC] Impossible de parser DATABASE_URL pour le diagnostic: {_e}", flush=True)
else:
    print("[DB DIAGNOSTIC] DATABASE_URL est VIDE/absente au demarrage !", flush=True)

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL manquante. Definis cette variable d'environnement avec "
        "ta chaine de connexion Postgres (ex: fournie par Neon), au format "
        "postgresql://utilisateur:motdepasse@hote/nom_base"
    )

# DB_LOCK etait un verrou global datant de l'epoque SQLite (fichier local,
# un seul ecrivain a la fois). Sur Postgres/Neon ce n'est plus necessaire -
# chaque get_db() ouvre sa propre connexion et Postgres gere nativement la
# concurrence. Le garder causait un bug grave : si UNE connexion (ex: le
# thread de polling IMAP en arriere-plan) mettait du temps a s'etablir
# (reveil de la base apres suspension, reseau lent...), TOUTE l'application
# se gelait derriere ce verrou unique - inscription/connexion incluses -
# jusqu'a ce que Gunicorn tue le worker apres son timeout (120s).
# Remplace par un verrou "no-op" : le code garde la meme structure
# "with DB_LOCK:" partout (zero risque de casser l'indentation), mais
# n'attend plus jamais rien.
DB_LOCK = contextlib.nullcontext()


class _CursorResult:
    """Enveloppe un curseur psycopg2 pour que .lastrowid fonctionne comme sur
    sqlite3, en lisant la valeur renvoyee par un INSERT ... RETURNING id."""
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class PGConnection:
    """Compatibilite avec l'API sqlite3 utilisee dans le reste du code :
    conn.execute(sql, params) directement sur la connexion (pas besoin de
    gerer un curseur explicitement), placeholders '?' traduits en '%s'."""
    def __init__(self, pg_conn):
        self._conn = pg_conn

    def execute(self, query, params=()):
        translated = query.replace("?", "%s")
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(translated, tuple(params) if params else None)

        if translated.strip().upper().startswith("INSERT") and "RETURNING" in translated.upper():
            row = cur.fetchone()
            lastrowid = row.get("id") if row else None
            # Garde la ligne disponible si l'appelant fait aussi un .fetchone()
            # (comportement souvent attendu apres un INSERT ... RETURNING).
            return _CursorResult(_FakeFetchedCursor([row] if row else []), lastrowid=lastrowid)

        return _CursorResult(cur)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


class _FakeFetchedCursor:
    """Petit adaptateur pour renvoyer une ligne deja recuperee (cas d'un
    INSERT ... RETURNING id, dont la ligne est consommee pour lastrowid mais
    doit rester disponible si l'appelant fait aussi .fetchone())."""
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


def get_db():
    # connect_timeout : evite qu'une base lente a repondre (reveil apres
    # suspension, souci reseau) ne bloque indefiniment l'appelant - au bout
    # de 10s, on echoue proprement (exception geree plus haut) plutot que
    # de risquer un blocage de plusieurs minutes.
    pg_conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    return PGConnection(pg_conn)


def init_db():
    with DB_LOCK:
        conn = get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id SERIAL PRIMARY KEY,
                channel TEXT,
                sender TEXT,
                text TEXT,
                score REAL,
                label TEXT,
                reasons TEXT,
                timestamp TEXT,
                corrected_label TEXT DEFAULT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sender_reputation (
                sender TEXT PRIMARY KEY,
                phishing_count INTEGER DEFAULT 0,
                total_count INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_sightings (
                id SERIAL PRIMARY KEY,
                domain TEXT,
                sender TEXT,
                analysis_id INTEGER,
                timestamp TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS community_reports (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                direction TEXT NOT NULL,
                reported_by_user_id INTEGER NOT NULL,
                timestamp TEXT,
                UNIQUE(sender, reported_by_user_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                api_key TEXT UNIQUE,
                created_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mailbox_connections (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                imap_host TEXT NOT NULL,
                imap_user TEXT NOT NULL,
                imap_password_enc TEXT NOT NULL,
                poll_seconds INTEGER DEFAULT 20,
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                purpose TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Migration douce : ajoute la colonne api_key si la base existait deja
        # sans elle (comptes crees avant ce systeme de cle API).
        user_cols = [r["column_name"] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
        ).fetchall()]
        if "api_key" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
            for row in conn.execute("SELECT id FROM users").fetchall():
                conn.execute("UPDATE users SET api_key = ? WHERE id = ?",
                             (secrets.token_hex(24), row["id"]))

        # Migration douce : ajoute la colonne email_verified si la base
        # existait deja sans elle (comptes crees avant ce systeme).
        if "email_verified" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE")

        # Migration douce : ajoute la colonne user_id si la base existait deja
        # sans elle (installations anterieures a l'authentification).
        cols = [r["column_name"] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'analyses'"
        ).fetchall()]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER")

        conn.commit()
        conn.close()


init_db()


def login_required(view):
    """Protege une route web (redirige vers /login) ou une route API (renvoie 401)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentification requise"}), 401
            return redirect(url_for("login_page", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def get_user_id_from_api_key():
    """Authentification par cle API : utilisee par l'extension navigateur et
    l'application mobile, qui n'ont pas de session de connexion (cookie).
    Cle attendue dans l'en-tete HTTP 'X-API-Key'."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        print("[API KEY DIAGNOSTIC] Aucun en-tete X-API-Key recu du tout.", flush=True)
        return None
    with DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT id FROM users WHERE api_key = ?", (api_key,)).fetchone()
        conn.close()
    masked = f"{api_key[:8]}...{api_key[-8:]} (longueur={len(api_key)})" if len(api_key) > 16 else f"'{api_key}' (longueur={len(api_key)})"
    print(f"[API KEY DIAGNOSTIC] Cle recue: {masked} -> trouvee={bool(row)}", flush=True)
    return row["id"] if row else None


def resolve_current_user_id():
    """Identifie l'utilisateur courant, que la requete vienne du tableau de
    bord web (session/cookie) ou d'un client externe (extension, mobile,
    poller) authentifie par cle API. Retourne None si aucun des deux."""
    if "user_id" in session:
        return session["user_id"]
    return get_user_id_from_api_key()


def api_key_or_login_required(view):
    """Comme login_required, mais accepte aussi une cle API valide (en-tete
    X-API-Key) - pour les routes appelees par l'extension ou l'appli mobile,
    qui n'ont pas de session navigateur."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if resolve_current_user_id() is None:
            return jsonify({"error": "authentification requise (session ou cle API)"}), 401
        return view(*args, **kwargs)
    return wrapped


def save_analysis(result, user_id=None):
    with DB_LOCK:
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO analyses (channel, sender, text, score, label, reasons, timestamp, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (result["channel"], result.get("sender", "inconnu"), result["text"],
             result["score"], result["label"], "|||".join(result["reasons"]),
             result["timestamp"], user_id)
        )
        analysis_id = cur.lastrowid

        sender = result.get("sender", "inconnu")
        is_threat = 1 if result["label"] in ("PHISHING", "SUSPECT") else 0
        conn.execute("""
            INSERT INTO sender_reputation (sender, phishing_count, total_count)
            VALUES (?, ?, 1)
            ON CONFLICT(sender) DO UPDATE SET
                phishing_count = sender_reputation.phishing_count + ?,
                total_count = sender_reputation.total_count + 1
        """, (sender, is_threat, is_threat))

        if is_threat:
            for domain in result.get("domains", []):
                # Un message frauduleux peut mentionner/imiter un domaine
                # legitime (ex: "gmail.com", "netflix.com") sans que ce
                # domaine soit lui-meme le lien piege - on ne l'ajoute donc
                # jamais aux campagnes partagees, pour eviter de flagger a
                # tort de grandes plateformes connues.
                if is_allowlisted_domain(domain):
                    continue
                conn.execute(
                    "INSERT INTO domain_sightings (domain, sender, analysis_id, timestamp) VALUES (?, ?, ?, ?)",
                    (domain, sender, analysis_id, result["timestamp"])
                )

        conn.commit()
        conn.close()
        return analysis_id


def get_active_campaigns():
    """Regroupe les domaines malveillants (exacts ou variantes typosquat proches)
    vus chez plusieurs expediteurs / occurrences = campagne coordonnee."""
    with DB_LOCK:
        conn = get_db()
        raw_rows = conn.execute("""
            SELECT domain, sender, timestamp FROM domain_sightings
        """).fetchall()
        conn.close()

    # Agregation manuelle par domaine (garde la liste reelle des expediteurs,
    # necessaire pour dessiner le graphe de campagne cote frontend).
    by_domain = {}
    for r in raw_rows:
        d = by_domain.setdefault(r["domain"], {"senders": set(), "occurrences": 0, "timestamps": []})
        d["senders"].add(r["sender"])
        d["occurrences"] += 1
        d["timestamps"].append(r["timestamp"])

    all_domains = []
    for domain, info in by_domain.items():
        all_domains.append({
            "domain": domain,
            "senders": info["senders"],
            "sender_count": len(info["senders"]),
            "occurrences": info["occurrences"],
            "first_seen": min(info["timestamps"]),
            "last_seen": max(info["timestamps"]),
        })
    all_domains.sort(key=lambda d: d["occurrences"], reverse=True)

    from urlintel import levenshtein

    # Union simple : regroupe les domaines dont la racine est a distance <= 2.
    # Deux garde-fous importants :
    # - on retire le prefixe "www." avant de comparer, sinon "www.bing.com" et
    #   "ww1.click" sont vus comme des variantes proches (comparaison "www" vs "ww1")
    # - on exige une base d'au moins 5 caracteres : sur des bases tres courtes,
    #   une distance de 2 represente une trop grande partie du mot et cree des
    #   faux rapprochements sans rapport (ex: "abc" vs "xyz" ne devrait pas clusteriser
    #   juste parce qu'ils sont courts).
    def domain_base(domain):
        d = domain.replace("www.", "", 1) if domain.startswith("www.") else domain
        return d.split(".")[0]

    clusters = []
    used = [False] * len(all_domains)
    for i, d in enumerate(all_domains):
        if used[i]:
            continue
        cluster = [d]
        used[i] = True
        base_i = domain_base(d["domain"])
        for j in range(i + 1, len(all_domains)):
            if used[j]:
                continue
            base_j = domain_base(all_domains[j]["domain"])
            if len(base_i) >= 5 and len(base_j) >= 5 and levenshtein(base_i, base_j) <= 2:
                cluster.append(all_domains[j])
                used[j] = True
        clusters.append(cluster)

    campaigns = []
    for cluster in clusters:
        all_senders = set()
        for c in cluster:
            all_senders |= c["senders"]
        total_occurrences = sum(c["occurrences"] for c in cluster)
        # Seuil de confirmation : il faut au moins 2 expediteurs DISTINCTS.
        # Volontairement plus strict qu'un simple comptage d'occurrences :
        # un seul expediteur qui repete le meme lien plusieurs fois ne doit
        # pas suffire a faire passer un domaine pour une "campagne confirmee"
        # (protection basique contre un signalement isole/errone qui polluerait
        # le tableau de bord).
        if len(all_senders) < 2:
            continue
        campaigns.append({
            "domain": " / ".join(c["domain"] for c in cluster),
            "domains": [c["domain"] for c in cluster],
            "senders": sorted(all_senders),
            "sender_count": len(all_senders),
            "occurrences": total_occurrences,
            "first_seen": min(c["first_seen"] for c in cluster),
            "last_seen": max(c["last_seen"] for c in cluster),
            "variant_cluster": len(cluster) > 1,
        })

    campaigns.sort(key=lambda c: c["occurrences"], reverse=True)
    return campaigns


def get_sender_reputation(sender):
    with DB_LOCK:
        conn = get_db()
        row = conn.execute(
            "SELECT phishing_count, total_count FROM sender_reputation WHERE sender = ?",
            (sender,)
        ).fetchone()
        threat_votes = conn.execute(
            "SELECT COUNT(DISTINCT reported_by_user_id) c FROM community_reports WHERE sender = ? AND direction = 'threat'",
            (sender,)
        ).fetchone()["c"]
        legit_votes = conn.execute(
            "SELECT COUNT(DISTINCT reported_by_user_id) c FROM community_reports WHERE sender = ? AND direction = 'legitimate'",
            (sender,)
        ).fetchone()["c"]
        conn.close()

    # Signal automatique : inchange, base uniquement sur le moteur (deja fiable
    # car ne depend d'aucune correction manuelle isolee).
    automatic_flag = bool(row and row["total_count"] > 1 and row["phishing_count"] >= 1)

    # Signal communautaire : ne compte que si au moins COMMUNITY_CONFIRM_THRESHOLD
    # comptes DIFFERENTS sont d'accord, et que l'avis "menace" l'emporte sur
    # l'avis "legitime" pour cet expediteur - un seul compte ne peut donc
    # jamais, a lui seul, faire basculer la reputation partagee.
    community_confirmed = threat_votes >= COMMUNITY_CONFIRM_THRESHOLD and threat_votes > legit_votes

    if automatic_flag or community_confirmed:
        return {
            "repeat_offender": True,
            "phishing_count": row["phishing_count"] if row else 0,
            "total_count": row["total_count"] if row else 0,
            "community_confirmed": community_confirmed,
            "community_votes": threat_votes,
        }
    return {"repeat_offender": False}

# Historique en memoire desactive : tout passe maintenant par SQLite (voir save_analysis)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html", error=None)

    email_addr = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    with DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email_addr,)).fetchone()
        total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        conn.close()
    print(f"[DB DIAGNOSTIC] [PID {os.getpid()}] Login tente email={email_addr} -> trouve={bool(row)} total_users_actuellement={total_users}", flush=True)

    if not row or not check_password_hash(row["password_hash"], password):
        return render_template("login.html", error="Email ou mot de passe incorrect."), 401

    session["user_id"] = row["id"]
    session["user_email"] = row["email"]
    session["user_name"] = row["display_name"] or row["email"].split("@")[0]

    next_url = request.args.get("next") or url_for("dashboard")
    return redirect(next_url)


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html", error=None)

    email_addr = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    display_name = request.form.get("display_name", "").strip()

    if not email_addr or not password:
        return render_template("register.html", error="Email et mot de passe requis."), 400
    if len(password) < 6:
        return render_template("register.html", error="Le mot de passe doit faire au moins 6 caracteres."), 400

    try:
        with DB_LOCK:
            conn = get_db()
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email_addr,)).fetchone()
            print(f"[DB DIAGNOSTIC] [PID {os.getpid()}] Verification email={email_addr} -> existing={bool(existing)}", flush=True)
            if existing:
                conn.close()
                return render_template("register.html", error="Un compte existe deja avec cet email."), 400

            is_first_user = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0

            new_api_key = secrets.token_hex(24)
            cur = conn.execute(
                "INSERT INTO users (email, password_hash, display_name, api_key, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
                (email_addr, generate_password_hash(password), display_name, new_api_key,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            user_id = cur.lastrowid

            # Le tout premier compte cree herite des analyses existantes qui
            # n'appartenaient encore a personne (donnees de test anterieures
            # a l'authentification) - evite un dashboard qui parait "vide"
            # au premier lancement apres cette mise a jour.
            if is_first_user:
                conn.execute("UPDATE analyses SET user_id = ? WHERE user_id IS NULL", (user_id,))

            conn.commit()
            print(f"[DB DIAGNOSTIC] [PID {os.getpid()}] Compte cree id={user_id} email={email_addr} - commit effectue.", flush=True)
            conn.close()
    except Exception as e:
        print(f"[REGISTER] Echec de creation de compte pour {email_addr}: {e}")
        return render_template(
            "register.html",
            error="Une erreur technique est survenue. Réessayez dans quelques instants."
        ), 500

    session["user_id"] = user_id
    session["user_email"] = email_addr
    session["user_name"] = display_name or email_addr.split("@")[0]

    threading.Thread(target=send_verification_email, args=(user_id, email_addr), daemon=True).start()
    return redirect(url_for("dashboard"))


@app.route("/verify-email/<token>")
def verify_email(token):
    user_id = consume_email_token(token, "verify")
    if not user_id:
        return render_template("login.html", error="Ce lien de vérification est invalide ou a expiré."), 400

    with DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE users SET email_verified = TRUE WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

    if session.get("user_id") == user_id:
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None, verified=True)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    if request.method == "GET":
        return render_template("forgot_password.html", sent=False, error=None)

    email_addr = request.form.get("email", "").strip().lower()
    with DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email_addr,)).fetchone()
        conn.close()

    # Toujours le meme message, que le compte existe ou non - evite de
    # laisser deviner quels emails sont inscrits sur FishGuard.
    if row:
        threading.Thread(target=send_password_reset_email, args=(row["id"], email_addr), daemon=True).start()
    return render_template("forgot_password.html", sent=True, error=None)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    if request.method == "GET":
        return render_template("reset_password.html", token=token, error=None)

    password = request.form.get("password", "")
    if len(password) < 6:
        return render_template("reset_password.html", token=token,
                                error="Le mot de passe doit faire au moins 6 caractères."), 400

    user_id = consume_email_token(token, "reset")
    if not user_id:
        return render_template("login.html", error="Ce lien de réinitialisation est invalide ou a expiré."), 400

    with DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                      (generate_password_hash(password), user_id))
        conn.commit()
        conn.close()

    session.clear()
    return render_template("login.html", error=None, password_reset=True)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", user_name=session.get("user_name"))


@app.route("/admin/users")
@login_required
def admin_users():
    """Vue de debogage : liste tous les comptes et un resume de leur activite.
    Reservee au tout premier compte cree (id=1), considere comme le
    proprietaire/administrateur du projet - les autres utilisateurs recoivent
    une erreur 403 s'ils essaient d'y acceder."""
    if session["user_id"] != 1:
        return jsonify({"error": "acces reserve a l'administrateur"}), 403

    with DB_LOCK:
        conn = get_db()
        users = conn.execute("""
            SELECT u.id, u.email, u.display_name, u.created_at,
                   COUNT(a.id) AS analyses_count,
                   (SELECT COUNT(*) FROM mailbox_connections m WHERE m.user_id = u.id) AS mailbox_count
            FROM users u
            LEFT JOIN analyses a ON a.user_id = u.id
            GROUP BY u.id
            ORDER BY u.id ASC
        """).fetchall()
        conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/api/my-key")
@login_required
def api_my_key():
    """Permet a l'extension (ou l'app mobile) de recuperer automatiquement
    la cle API de l'utilisateur DEJA CONNECTE dans son navigateur sur
    fishguard.me, via le cookie de session - evite le copier-coller manuel
    depuis la page Reglages lors de la premiere configuration. Protege par
    @login_required : ne fonctionne que si un vrai cookie de session valide
    est envoye (jamais accessible a un tiers non authentifie)."""
    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT api_key, display_name FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
    if not user:
        return jsonify({"error": "utilisateur introuvable"}), 404
    return jsonify({"api_key": user["api_key"], "user_name": user["display_name"]})


@app.route("/settings")
@login_required
def settings_page():
    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        mailbox = conn.execute(
            "SELECT * FROM mailbox_connections WHERE user_id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
    return render_template("settings.html", user=user, mailbox=mailbox, error=None, saved=False,
                            user_name=session.get("user_name"))


@app.route("/settings/regenerate-key", methods=["POST"])
@login_required
def regenerate_api_key():
    new_key = secrets.token_hex(24)
    with DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, session["user_id"]))
        conn.commit()
        conn.close()
    return redirect(url_for("settings_page"))


@app.route("/settings/change-email", methods=["POST"])
@login_required
def change_email():
    new_email = request.form.get("new_email", "").strip().lower()
    password = request.form.get("current_password", "")

    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

        if not check_password_hash(user["password_hash"], password):
            conn.close()
            return _settings_with_error("Mot de passe actuel incorrect.")

        existing = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?",
                                 (new_email, session["user_id"])).fetchone()
        if existing:
            conn.close()
            return _settings_with_error("Cet email est déjà utilisé par un autre compte.")

        # Changer d'email invalide la verification precedente : la nouvelle
        # adresse doit etre reconfirmee avant d'etre consideree fiable.
        conn.execute("UPDATE users SET email = ?, email_verified = FALSE WHERE id = ?",
                      (new_email, session["user_id"]))
        conn.commit()
        conn.close()

    session["user_email"] = new_email
    threading.Thread(target=send_verification_email, args=(session["user_id"], new_email), daemon=True).start()
    return redirect(url_for("settings_page"))


@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(new_password) < 6:
        return _settings_with_error("Le nouveau mot de passe doit contenir au moins 6 caracteres.")
    if new_password != confirm_password:
        return _settings_with_error("Les deux mots de passe ne correspondent pas.")

    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

        if not check_password_hash(user["password_hash"], current_password):
            conn.close()
            return _settings_with_error("Mot de passe actuel incorrect.")

        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                      (generate_password_hash(new_password), session["user_id"]))
        conn.commit()
        conn.close()

    return redirect(url_for("settings_page"))


@app.route("/settings/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    global _LAST_EMAIL_ATTEMPT
    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
    if user and not user["email_verified"]:
        threading.Thread(target=send_verification_email, args=(user["id"], user["email"]), daemon=True).start()
    else:
        _LAST_EMAIL_ATTEMPT = {
            "moment": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "resultat": "resend_verification: envoi NON declenche",
            "user_trouve": bool(user),
            "email_verified_en_base": user["email_verified"] if user else None,
        }
    return redirect(url_for("settings_page"))


def _settings_with_error(message):
    with DB_LOCK:
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        mailbox = conn.execute(
            "SELECT * FROM mailbox_connections WHERE user_id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
    return render_template("settings.html", user=user, mailbox=mailbox, error=message, saved=False,
                            user_name=session.get("user_name")), 400


@app.route("/settings/mailbox", methods=["POST"])
@login_required
def connect_mailbox():
    imap_host = request.form.get("imap_host", "").strip()
    imap_user = request.form.get("imap_user", "").strip()
    imap_password = request.form.get("imap_password", "").strip()
    poll_seconds = int(request.form.get("poll_seconds", 20) or 20)

    if not (imap_host and imap_user and imap_password):
        with DB_LOCK:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            conn.close()
        return render_template("settings.html", user=user, mailbox=None,
                                error="Hote, email et mot de passe requis.", saved=False,
                                user_name=session.get("user_name")), 400

    with DB_LOCK:
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM mailbox_connections WHERE user_id = ?", (session["user_id"],)
        ).fetchone()
        enc_password = encrypt_secret(imap_password)
        if existing:
            conn.execute(
                "UPDATE mailbox_connections SET imap_host=?, imap_user=?, imap_password_enc=?, poll_seconds=? WHERE id=?",
                (imap_host, imap_user, enc_password, poll_seconds, existing["id"])
            )
        else:
            conn.execute(
                "INSERT INTO mailbox_connections (user_id, imap_host, imap_user, imap_password_enc, poll_seconds, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session["user_id"], imap_host, imap_user, enc_password, poll_seconds,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
        conn.commit()
        conn.close()
    return redirect(url_for("settings_page"))


@app.route("/settings/mailbox/delete", methods=["POST"])
@login_required
def disconnect_mailbox():
    with DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM mailbox_connections WHERE user_id = ?", (session["user_id"],))
        conn.commit()
        conn.close()
    return redirect(url_for("settings_page"))


@app.route("/check-url")
def check_url_page():
    return render_template("check_url.html", user_name=session.get("user_name"))


@app.route("/security-checkup")
def security_checkup_page():
    return render_template("security_checkup.html", user_name=session.get("user_name"))


@app.route("/check-qr")
def check_qr_page():
    return render_template("check_qr.html", user_name=session.get("user_name"))


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact_page():
    contact_email = os.getenv("SMTP_USER") or "contact@fishguard.me"

    if request.method == "GET":
        return render_template(
            "contact.html",
            user_name=session.get("user_name"),
            user_email=session.get("user_email"),
            contact_email=contact_email,
            sent=False, error=None,
        )

    name = request.form.get("name", "").strip() or session.get("user_name") or "Utilisateur FishGuard"
    from_email = request.form.get("email", "").strip() or session.get("user_email")
    subject = request.form.get("subject", "").strip() or "(sans objet)"
    message_body = request.form.get("message", "").strip()

    if not from_email or not message_body:
        return render_template(
            "contact.html",
            user_name=session.get("user_name"),
            user_email=session.get("user_email"),
            contact_email=contact_email,
            sent=False, error="Email et message sont requis.",
        ), 400

    threading.Thread(
        target=send_contact_message,
        args=(name, from_email, subject, message_body),
        daemon=True,
    ).start()

    return render_template(
        "contact.html",
        user_name=session.get("user_name"),
        user_email=from_email,
        contact_email=contact_email,
        sent=True, error=None,
    )


@app.route("/api/threat-intel", methods=["POST"])
def api_threat_intel():
    """Enrichissement a la demande via VirusTotal. N'est jamais appele
    automatiquement dans le flux d'analyse principal (limite de 4 req/min
    sur le tier gratuit VirusTotal)."""
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url manquante"}), 400
    result = check_virustotal(url)
    return jsonify(result)


@app.route("/api/urlscan", methods=["POST"])
def api_urlscan():
    """Enrichissement a la demande via URLScan.io (capture d'ecran + analyse visuelle).
    Peut prendre jusqu'a une dizaine de secondes - jamais appele automatiquement."""
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url manquante"}), 400
    result = check_urlscan(url)
    return jsonify(result)


@app.route("/outlook-addin/<path:filename>")
def outlook_addin_files(filename):
    addin_dir = os.path.join(os.path.dirname(__file__), "outlook-addin")
    return send_from_directory(addin_dir, filename)


@app.route("/api/feed")
@login_required
def api_feed():
    limit = min(int(request.args.get("limit", 5)), 100)
    offset = int(request.args.get("offset", 0))
    channel_filter = request.args.get("channel", "").strip()
    date_filter = request.args.get("date", "").strip()  # format attendu: YYYY-MM-DD
    label_filter = request.args.get("label", "").strip().upper()  # PHISHING / SUSPECT / LEGITIME

    # Chaque utilisateur ne voit que ses propres analyses.
    where_clauses = ["user_id = ?"]
    params = [session["user_id"]]
    if channel_filter:
        where_clauses.append("channel = ?")
        params.append(channel_filter)
    if date_filter:
        where_clauses.append("timestamp LIKE ?")
        params.append(f"{date_filter}%")
    if label_filter in ("PHISHING", "SUSPECT", "LEGITIME"):
        where_clauses.append("COALESCE(corrected_label, label) = ?")
        params.append(label_filter)
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with DB_LOCK:
        conn = get_db()
        total = conn.execute(
            f"SELECT COUNT(*) c FROM analyses {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM analyses {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        channels = conn.execute(
            "SELECT DISTINCT channel FROM analyses WHERE user_id = ? ORDER BY channel",
            (session["user_id"],)
        ).fetchall()
        conn.close()

    feed = []
    for r in rows:
        feed.append({
            "id": r["id"],
            "channel": r["channel"],
            "sender": r["sender"],
            "text": r["text"],
            "score": r["score"],
            "label": r["corrected_label"] or r["label"],
            "original_label": r["label"],
            "corrected": r["corrected_label"] is not None,
            "reasons": r["reasons"].split("|||") if r["reasons"] else [],
            "timestamp": r["timestamp"],
        })

    return jsonify({
        "items": feed,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + limit) < total,
        "available_channels": [c["channel"] for c in channels],
    })


@app.route("/api/stats")
@login_required
def api_stats():
    uid = session["user_id"]
    with DB_LOCK:
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) c FROM analyses WHERE user_id = ?", (uid,)).fetchone()["c"]
        threats = conn.execute(
            "SELECT COUNT(*) c FROM analyses WHERE user_id = ? AND label IN ('PHISHING','SUSPECT')", (uid,)
        ).fetchone()["c"]
        by_channel = conn.execute(
            "SELECT channel, COUNT(*) c FROM analyses WHERE user_id = ? GROUP BY channel", (uid,)
        ).fetchall()
        # Reputation des expediteurs : reste globale (intelligence partagee entre
        # utilisateurs, ne revele pas le contenu des messages de chacun).
        repeat_offenders = conn.execute(
            "SELECT COUNT(*) c FROM sender_reputation WHERE phishing_count >= 1 AND total_count > 1"
        ).fetchone()["c"]
        corrections = conn.execute(
            "SELECT COUNT(*) c FROM analyses WHERE user_id = ? AND corrected_label IS NOT NULL", (uid,)
        ).fetchone()["c"]
        conn.close()

    pct = round((threats / total) * 100, 1) if total else 0
    return jsonify({
        "total": total,
        "threats": threats,
        "threat_pct": pct,
        "by_channel": {r["channel"]: r["c"] for r in by_channel},
        "repeat_offenders": repeat_offenders,
        "corrections": corrections,
    })


@app.route("/api/campaigns")
def api_campaigns():
    return jsonify(get_active_campaigns())


@app.route("/api/analytics")
@login_required
def api_analytics():
    """Donnees agregees pour les graphiques du tableau de bord :
    repartition par label, taux de menace par canal, tendance sur 14 jours.
    Toujours filtre sur les analyses du seul utilisateur connecte."""
    uid = session["user_id"]
    with DB_LOCK:
        conn = get_db()
        by_label_rows = conn.execute("""
            SELECT COALESCE(corrected_label, label) AS lbl, COUNT(*) c
            FROM analyses WHERE user_id = ? GROUP BY lbl
        """, (uid,)).fetchall()
        by_channel_rows = conn.execute("""
            SELECT channel,
                   COUNT(*) AS total,
                   SUM(CASE WHEN COALESCE(corrected_label, label) IN ('PHISHING','SUSPECT') THEN 1 ELSE 0 END) AS threats
            FROM analyses WHERE user_id = ? GROUP BY channel
        """, (uid,)).fetchall()
        timeline_rows = conn.execute("""
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) c
            FROM analyses WHERE user_id = ? GROUP BY day ORDER BY day DESC LIMIT 14
        """, (uid,)).fetchall()
        conn.close()

    by_label = {"PHISHING": 0, "SUSPECT": 0, "LEGITIME": 0}
    for r in by_label_rows:
        if r["lbl"] in by_label:
            by_label[r["lbl"]] = r["c"]

    by_channel = [
        {
            "channel": r["channel"],
            "total": r["total"],
            "threats": r["threats"] or 0,
            "threat_pct": round((r["threats"] or 0) / r["total"] * 100, 1) if r["total"] else 0,
        }
        for r in by_channel_rows
    ]
    by_channel.sort(key=lambda c: c["total"], reverse=True)

    timeline = [{"date": r["day"], "count": r["c"]} for r in timeline_rows]
    timeline.reverse()  # chronologique (plus ancien -> plus recent)

    return jsonify({
        "by_label": by_label,
        "by_channel": by_channel,
        "timeline": timeline,
    })


@app.route("/api/feedback", methods=["POST"])
@login_required
def api_feedback():
    """Permet de corriger une analyse (faux positif/negatif) - alimente
    l'amelioration continue ET, sous condition, la reputation partagee
    entre utilisateurs.

    Important : une correction seule n'affecte JAMAIS directement les
    autres comptes. Elle enregistre un "vote" individuel (une personne =
    une voix par expediteur, modifiable si elle change d'avis). La
    reputation partagee (repeat_offender, campagnes) n'est mise a jour que
    lorsque COMMUNITY_CONFIRM_THRESHOLD comptes DIFFERENTS sont
    independamment arrives a la meme conclusion - voir get_sender_reputation().
    Ca evite qu'un compte isole (erreur ou malveillance) ne fausse ce que
    voient tous les autres utilisateurs.

    Restreint aux analyses appartenant a l'utilisateur connecte (on ne peut
    corriger que ses propres analyses, mais le VOTE qui en resulte compte
    bien vers le consensus partage)."""
    data = request.get_json(force=True)
    analysis_id = data.get("id")
    corrected_label = data.get("label")
    if not analysis_id or corrected_label not in ("PHISHING", "SUSPECT", "LEGITIME"):
        return jsonify({"error": "parametres invalides"}), 400

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    direction = "threat" if corrected_label in ("PHISHING", "SUSPECT") else "legitimate"

    with DB_LOCK:
        conn = get_db()
        analysis = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
        if not analysis or analysis["user_id"] != session["user_id"]:
            conn.close()
            return jsonify({"error": "analyse introuvable"}), 404

        conn.execute(
            "UPDATE analyses SET corrected_label = ? WHERE id = ?",
            (corrected_label, analysis_id)
        )

        sender = analysis["sender"] or "inconnu"

        # Un vote par compte et par expediteur - modifiable si la personne
        # change d'avis, mais ne compte jamais deux fois.
        conn.execute("""
            INSERT INTO community_reports (sender, direction, reported_by_user_id, timestamp)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(sender, reported_by_user_id) DO UPDATE SET
                direction = EXCLUDED.direction,
                timestamp = EXCLUDED.timestamp
        """, (sender, direction, session["user_id"], now_str))

        threat_votes = conn.execute(
            "SELECT COUNT(DISTINCT reported_by_user_id) c FROM community_reports WHERE sender = ? AND direction = 'threat'",
            (sender,)
        ).fetchone()["c"]

        # Des que le consensus est atteint (et confirme par ce vote), les
        # domaines de CETTE analyse rejoignent les campagnes partagees -
        # chaque contributeur au consensus ajoute ses propres domaines.
        if direction == "threat" and threat_votes >= COMMUNITY_CONFIRM_THRESHOLD:
            already_linked = conn.execute(
                "SELECT 1 FROM domain_sightings WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if not already_linked:
                for domain in analyze_urls(analysis["text"])[2]:
                    if is_allowlisted_domain(domain):
                        continue
                    conn.execute(
                        "INSERT INTO domain_sightings (domain, sender, analysis_id, timestamp) VALUES (?, ?, ?, ?)",
                        (domain, sender, analysis_id, analysis["timestamp"])
                    )

        conn.commit()
        conn.close()

    # Ajoute cet exemple corrige au jeu de donnees pour un futur re-entrainement
    # (utile independamment du consensus - c'est un signal d'entrainement,
    # pas une affirmation partagee en temps reel).
    label_int = 1 if corrected_label in ("PHISHING", "SUSPECT") else 0
    text_escaped = analysis["text"].replace('"', '""')
    with open(os.path.join(os.path.dirname(__file__), "data", "feedback.csv"), "a", encoding="utf-8") as f:
        f.write(f'"{text_escaped}",{label_int}\n')

    return jsonify({"ok": True})


@app.route("/api/analyze", methods=["POST"])
@api_key_or_login_required
def api_analyze():
    """Point d'entree generique : email, SMS simule, ou autre canal futur.
    Accepte soit une session navigateur (dashboard), soit une cle API en
    en-tete X-API-Key (extension, application mobile)."""
    data = request.get_json(force=True)
    text = data.get("text", "")
    channel = data.get("channel", "sms")
    sender = data.get("sender", "inconnu")

    if not text.strip():
        return jsonify({"error": "texte vide"}), 400

    # web-link (garde de liens universelle) et url-check (verificateur manuel)
    # envoient un LIEN BRUT, pas un message - voir analyzer.analyze() pour le detail.
    url_only = channel in ("web-link", "url-check")

    result = analyzer.analyze(text, channel=channel, url_only=url_only)
    result["sender"] = sender
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    reputation = get_sender_reputation(sender)
    if reputation["repeat_offender"]:
        result["reasons"].append(
            f"Expediteur recidiviste : deja flagge {reputation['phishing_count']}/{reputation['total_count']} fois"
        )

    analysis_id = save_analysis(result, user_id=resolve_current_user_id())
    result["id"] = analysis_id
    result["reputation"] = reputation
    return jsonify(result)


# Extensions executables/scripts couramment utilisees pour deguiser un malware
# en document inoffensif (double extension, ex: "facture.pdf.exe").
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "jar", "msi", "msp", "ps1", "psm1", "wsf", "wsh", "hta", "reg", "lnk",
    "apk", "docm", "xlsm", "pptm",
}
# Extensions "documents" derriere lesquelles on s'attend a NE PAS trouver
# une extension executable juste apres (le signe d'un deguisement).
DOCUMENT_LOOKING_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "zip", "rar",
}
RLO_CHAR = "\u202e"  # caractere d'inversion de sens d'ecriture (Right-to-Left Override)

# Marqueurs structurels d'un PDF piege - technique standard des scanners PDF
# legers (meme principe que l'outil pdfid) : on cherche ces mots-cles
# directement dans les OCTETS BRUTS du fichier, sans dependre du texte
# visible ni du nom du fichier. Un nom de fichier propre ("facture.pdf")
# peut tres bien cacher un PDF dont le contenu reel est piege.
PDF_MALWARE_KEYWORDS = {
    b"/JavaScript": ("PHISHING", "Contient du code JavaScript embarque - vecteur d'exploitation classique dans les lecteurs PDF vulnerables"),
    b"/JS": ("PHISHING", "Action JavaScript detectee dans la structure du PDF"),
    b"/Launch": ("PHISHING", "Le PDF peut lancer un programme ou fichier externe automatiquement a l'ouverture"),
    b"/OpenAction": ("SUSPECT", "Le PDF declenche une action automatique des l'ouverture du document"),
    b"/EmbeddedFile": ("SUSPECT", "Un fichier est embarque a l'interieur du PDF - peut cacher un executable"),
    b"/AA": ("SUSPECT", "Actions automatiques additionnelles definies, declenchees par des evenements du document"),
    b"/RichMedia": ("SUSPECT", "Contenu multimedia enrichi - vecteur parfois utilise pour des exploits"),
}
_LABEL_PRIORITY = {"LEGITIME": 0, "SUSPECT": 1, "PHISHING": 2}


def scan_pdf_structure(file_bytes):
    """Inspecte le contenu BINAIRE reel du PDF (pas le texte affiche, pas le
    nom de fichier) a la recherche de mecanismes connus d'exploitation :
    JavaScript embarque, action de lancement automatique, fichier cache a
    l'interieur du PDF. Retourne (label, reasons)."""
    findings = []
    worst = "LEGITIME"
    for keyword, (severity, reason) in PDF_MALWARE_KEYWORDS.items():
        if keyword in file_bytes:
            findings.append(reason)
            if _LABEL_PRIORITY[severity] > _LABEL_PRIORITY[worst]:
                worst = severity
    return worst, findings


def scan_office_macros(file_bytes):
    """Extrait et analyse les macros VBA ET XLM (Excel 4.0, un format plus
    ancien et distinct de VBA, parfois utilise specifiquement pour echapper
    aux scanners qui ne cherchent que VBA) d'un document Office.
    S'appuie sur oletools, la reference standard pour ce type d'analyse.

    Retourne (label, reasons, has_macros: bool)."""
    try:
        vba = VBA_Parser("piece_jointe", data=file_bytes)
    except Exception:
        return "LEGITIME", [], False

    try:
        has_vba = vba.detect_vba_macros()
        has_xlm = False
        try:
            has_xlm = vba.detect_xlm_macros()
        except Exception:
            pass  # pas tous les formats de fichier supportent la detection XLM

        if not has_vba and not has_xlm:
            return "LEGITIME", [], False

        reasons = []
        worst = "SUSPECT"  # presence de macros = au minimum SUSPECT par principe
        seen = set()

        if has_vba:
            results = vba.analyze_macros()
            if results:
                for kw_type, keyword, description in results:
                    key = (kw_type, keyword)
                    if key in seen:
                        continue
                    seen.add(key)
                    reasons.append(f"Macro VBA — {description} (mot-cle : {keyword})")
                    if kw_type in ("AutoExec", "Suspicious", "IOC"):
                        worst = "PHISHING" if kw_type != "AutoExec" or len(results) > 1 else worst
            else:
                reasons.append("Le document contient des macros VBA (aucun signal malveillant specifique detecte, mais toute macro merite prudence)")

        if has_xlm:
            reasons.append(
                "Le document contient des macros Excel 4.0 (XLM) — un format plus ancien "
                "et moins surveille que VBA, parfois choisi specifiquement pour cette raison"
            )
            worst = "PHISHING" if worst == "PHISHING" else "SUSPECT"

        return worst, reasons, True
    finally:
        vba.close()


# Mots-cles reveles par la ligne de commande/cible d'un raccourci Windows
# (.lnk) qui trahissent une intention malveillante - technique tres utilisee
# dans de vraies campagnes reelles (Emotet, Qakbot) : le raccourci parait
# anodin ("Facture.pdf.lnk") mais lance en realite une commande cachee.
LNK_SUSPICIOUS_KEYWORDS = {
    "powershell": "Lance PowerShell, souvent utilise pour executer du code cache",
    "cmd.exe": "Lance l'invite de commandes Windows",
    "mshta": "Lance mshta.exe, technique classique pour executer du HTML/JS malveillant",
    "wscript": "Lance le moteur de script Windows (WScript)",
    "cscript": "Lance le moteur de script Windows (CScript)",
    "certutil": "Utilise certutil.exe, souvent detourne pour telecharger des fichiers",
    "bitsadmin": "Utilise BITSAdmin, souvent detourne pour telecharger des fichiers en arriere-plan",
    "-enc": "Commande PowerShell encodee en Base64 - technique d'obfuscation courante",
    "-windowstyle hidden": "Execution en fenetre cachee, pour ne rien montrer a l'utilisateur",
    "downloadfile": "Telechargement de fichier depuis Internet",
    "downloadstring": "Telechargement et execution de code depuis Internet",
    "invoke-expression": "Execution dynamique de code (obfuscation courante)",
    " iex ": "Execution dynamique de code (raccourci PowerShell courant dans les malwares)",
}


def scan_lnk_file(file_bytes):
    """Analyse un raccourci Windows (.lnk). Un raccourci peut sembler pointer
    vers un document alors qu'il lance en realite une commande systeme
    cachee (PowerShell, cmd, etc.) - technique tres utilisee dans de vraies
    campagnes de malware par email. Retourne (label, reasons)."""
    try:
        lnk = lnk_file(io.BytesIO(file_bytes))
        data = lnk.get_json()
    except Exception:
        return "LEGITIME", []

    target_items = data.get("target", {}).get("items", []) or []
    target_path = "\\".join(item.get("primary_name", "") for item in target_items if item.get("primary_name"))
    args = data.get("data", {}).get("command_line_arguments", "") or ""
    combined = f"{target_path} {args}".lower()

    reasons = []
    for kw, desc in LNK_SUSPICIOUS_KEYWORDS.items():
        if kw in combined:
            reasons.append(f"{desc} (detecte dans la cible/commande du raccourci)")

    return ("PHISHING" if reasons else "LEGITIME"), reasons


def scan_zip_archive(file_bytes):
    """Inspecte une archive ZIP jointe : recherche un fichier a risque cache
    a l'interieur, ou detecte une archive protegee par mot de passe (qui
    empeche toute inspection - une technique d'evasion tres frequente pour
    faire passer un fichier malveillant a travers les filtres automatiques,
    puisque le mot de passe est generalement donne dans le corps du message
    lui-meme). Retourne (label, reasons)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        return "LEGITIME", []

    is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    if is_encrypted:
        return "SUSPECT", [
            "Archive protegee par mot de passe : impossible d'inspecter le contenu reel. "
            "C'est une technique frequemment utilisee pour faire passer un fichier malveillant "
            "a travers les filtres de securite automatiques"
        ]

    reasons = []
    for info in zf.infolist():
        inner_suspicious, inner_reasons = check_suspicious_filename(info.filename)
        if inner_suspicious:
            for r in inner_reasons:
                reasons.append(f"Dans l'archive, {info.filename} : {r}")

    return ("PHISHING" if reasons else "LEGITIME"), reasons


def scan_7z_archive(file_bytes):
    """Meme principe que scan_zip_archive, pour le format 7z (py7zr est une
    bibliotheque Python pure, sans dependance systeme externe)."""
    try:
        archive = py7zr.SevenZipFile(io.BytesIO(file_bytes))
    except Exception:
        return "LEGITIME", []

    reasons = []
    try:
        if archive.needs_password():
            return "SUSPECT", [
                "Archive 7z protegee par mot de passe : impossible d'inspecter le contenu reel. "
                "Technique frequemment utilisee pour echapper aux filtres de securite automatiques"
            ]
        for name in archive.getnames():
            inner_suspicious, inner_reasons = check_suspicious_filename(name)
            if inner_suspicious:
                for r in inner_reasons:
                    reasons.append(f"Dans l'archive 7z, {name} : {r}")
    finally:
        archive.close()

    return ("PHISHING" if reasons else "LEGITIME"), reasons


def scan_tar_archive(file_bytes):
    """Meme principe pour les archives TAR/TAR.GZ/TAR.BZ2 - couvert
    nativement par le module standard tarfile, sans dependance supplementaire."""
    try:
        tar = tarfile.open(fileobj=io.BytesIO(file_bytes))
    except Exception:
        return "LEGITIME", []

    reasons = []
    for member in tar.getmembers():
        inner_suspicious, inner_reasons = check_suspicious_filename(member.name)
        if inner_suspicious:
            for r in inner_reasons:
                reasons.append(f"Dans l'archive tar, {member.name} : {r}")
    tar.close()

    return ("PHISHING" if reasons else "LEGITIME"), reasons


def check_suspicious_filename(filename):
    """Detecte les techniques classiques de deguisement de fichier malveillant :
    double extension (facture.pdf.exe), caractere RLO (inversion visuelle du
    nom pour cacher la vraie extension), ou extension executable directe.
    Retourne (is_suspicious: bool, reasons: list[str])."""
    reasons = []
    if not filename:
        return False, reasons

    if RLO_CHAR in filename:
        reasons.append(
            "Le nom de fichier contient un caractere d'inversion (RLO) qui peut "
            "masquer visuellement la vraie extension du fichier"
        )

    parts = filename.rsplit(".", 2)  # jusqu'a 2 extensions (ex: facture.pdf.exe -> ['facture','pdf','exe'])
    if len(parts) >= 2:
        last_ext = parts[-1].lower()
        if last_ext in DANGEROUS_EXTENSIONS:
            if len(parts) == 3 and parts[-2].lower() in DOCUMENT_LOOKING_EXTENSIONS:
                reasons.append(
                    f"Double extension suspecte : le fichier ressemble a un "
                    f".{parts[-2]} mais est en realite un .{last_ext} executable"
                )
            else:
                reasons.append(
                    f"Extension de fichier a risque (.{last_ext}) - potentiellement executable"
                )

    return (len(reasons) > 0), reasons


@app.route("/api/analyze-attachment", methods=["POST"])
@api_key_or_login_required
def api_analyze_attachment():
    """Analyse une piece jointe (aujourd'hui : PDF) recue par email.

    Deux niveaux de verification, independants du contenu du message
    principal :
      1. Le NOM du fichier lui-meme (double extension, caractere RLO,
         extension executable deguisee) - s'applique a n'importe quel type
         de fichier, meme sans l'ouvrir.
      2. Si le fichier est un vrai PDF lisible : extraction du texte et des
         liens qu'il contient, puis passage par le meme moteur d'analyse
         que pour un message classique.

    Attendu : multipart/form-data avec un champ 'file' et un champ
    optionnel 'filename' (sinon le nom du fichier uploade est utilise)."""
    if "file" not in request.files:
        return jsonify({"error": "aucun fichier fourni"}), 400

    uploaded = request.files["file"]
    filename = request.form.get("filename", uploaded.filename or "piece_jointe")

    filename_suspicious, filename_reasons = check_suspicious_filename(filename)

    file_bytes = uploaded.read()
    is_pdf = filename.lower().endswith(".pdf") and file_bytes[:4] == b"%PDF"

    # Analyse structurelle du contenu BINAIRE reel, independante du nom de
    # fichier et du texte visible - c'est elle qui detecte un PDF piege
    # meme quand le nom de fichier parait parfaitement legitime.
    structure_label, structure_reasons = ("LEGITIME", [])
    if file_bytes[:4] == b"%PDF":  # verifie le contenu reel, pas juste l'extension du nom
        structure_label, structure_reasons = scan_pdf_structure(file_bytes)

    # Detection d'un document Office par SIGNATURE BINAIRE reelle (pas
    # l'extension du nom) : OLE2 pour les anciens formats .doc/.xls, ZIP
    # pour les formats modernes .docx/.docm/.xlsx/.xlsm - VBA_Parser gere
    # les deux automatiquement et ne remonte rien si le fichier n'a pas
    # de macros (donc aucun risque de faux positif sur un vrai .docx propre).
    is_ole2 = file_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_zip_signature = file_bytes[:4] == b"PK\x03\x04"
    is_office_doc = is_ole2 or is_zip_signature
    macro_label, macro_reasons, has_macros = ("LEGITIME", [], False)
    if is_office_doc and not is_pdf:
        macro_label, macro_reasons, has_macros = scan_office_macros(file_bytes)

    # Un fichier ZIP peut aussi etre une simple archive (pas un document
    # Office) contenant un executable cache, ou etre protege par mot de
    # passe pour echapper a l'inspection - verifie dans tous les cas ou la
    # signature ZIP est presente, meme si c'est aussi un document Office
    # (un vrai .docx propre n'a rien de suspect a l'interieur de son zip).
    zip_label, zip_reasons = ("LEGITIME", [])
    if is_zip_signature:
        zip_label, zip_reasons = scan_zip_archive(file_bytes)

    # Raccourci Windows (.lnk) - signature binaire "L\x00\x00\x00..."
    is_lnk = file_bytes[:4] == b"L\x00\x00\x00"
    lnk_label, lnk_reasons = ("LEGITIME", [])
    if is_lnk:
        lnk_label, lnk_reasons = scan_lnk_file(file_bytes)

    # 7z - signature binaire "7z\xbc\xaf\x27\x1c"
    is_7z = file_bytes[:6] == b"7z\xbc\xaf\x27\x1c"
    sevenz_label, sevenz_reasons = ("LEGITIME", [])
    if is_7z:
        sevenz_label, sevenz_reasons = scan_7z_archive(file_bytes)

    # TAR (avec ou sans compression gzip/bzip2) - gzip commence par 1f 8b,
    # bzip2 par "BZh", un tar non compresse a "ustar" a l'offset 257.
    is_tar = (
        file_bytes[:2] == b"\x1f\x8b"
        or file_bytes[:3] == b"BZh"
        or (len(file_bytes) > 262 and file_bytes[257:262] == b"ustar")
    )
    tar_label, tar_reasons = ("LEGITIME", [])
    if is_tar:
        tar_label, tar_reasons = scan_tar_archive(file_bytes)

    # Verification universelle par empreinte VirusTotal - fonctionne pour
    # N'IMPORTE QUEL type de fichier, y compris RAR (que l'on ne parse pas
    # nous-meme, faute de binaire unrar disponible sur l'hebergeur actuel)
    # et les fichiers deliberement malformes pour exploiter une faille du
    # lecteur (VirusTotal agrege des moteurs a analyse comportementale,
    # au-dela de ce que des regles statiques locales peuvent detecter).
    # Volontairement best-effort : n'importe quelle indisponibilite
    # (cle absente, quota depasse, hash inconnu) degrade proprement sans
    # jamais faire echouer l'analyse dans son ensemble.
    vt_result = check_virustotal_file(file_bytes)
    vt_label = "LEGITIME"
    vt_reasons = []
    if vt_result["available"] and vt_result["found"]:
        if vt_result["malicious"] > 0:
            vt_label = "PHISHING"
            vt_reasons.append(f"VirusTotal : {vt_result['message']}")
        elif vt_result["suspicious"] > 0:
            vt_label = "SUSPECT"
            vt_reasons.append(f"VirusTotal : {vt_result['message']}")

    extracted_text = ""
    links_found = []
    link_analyses = []
    pdf_parse_error = None

    if is_pdf:
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                extracted_text += (page.extract_text() or "") + "\n"
                annotations = page.get("/Annots")
                if annotations:
                    for annot in annotations:
                        obj = annot.get_object()
                        uri = obj.get("/A", {}).get("/URI") if obj.get("/A") else None
                        if uri:
                            links_found.append(uri)
            # Filet de securite : recupere aussi les URLs presentes dans le texte brut
            # (au cas ou elles ne soient pas encodees comme vraies annotations de lien)
            _, _, text_domains = analyze_urls(extracted_text)
            for url_match in re.findall(r"https?://[^\s\)\]\"'<>]+", extracted_text):
                if url_match not in links_found:
                    links_found.append(url_match)
        except Exception as e:
            pdf_parse_error = str(e)
    elif filename.lower().endswith(".pdf"):
        # extension .pdf mais signature binaire non conforme -> tres suspect en soi
        filename_suspicious = True
        filename_reasons.append(
            "Le fichier porte l'extension .pdf mais son contenu binaire ne "
            "correspond pas a un vrai PDF - signe possible de deguisement"
        )

    # Analyse du texte extrait (comme un message classique)
    text_analysis = None
    if extracted_text.strip():
        text_analysis = analyzer.analyze(extracted_text, channel="pdf-attachment", url_only=False)

    # Analyse individuelle de chaque lien trouve dans le PDF
    for url in links_found[:15]:  # limite raisonnable
        link_result = analyzer.analyze(url, channel="pdf-attachment-link", url_only=True)
        link_analyses.append({
            "url": url,
            "label": link_result["label"],
            "score": link_result["score"],
            "reasons": link_result["reasons"],
        })

    # Verdict global : le pire de tous les signaux disponibles - un seul
    # suffit a alerter.
    candidate_labels = [
        structure_label, macro_label, zip_label, lnk_label,
        sevenz_label, tar_label, vt_label,
    ]
    if filename_suspicious:
        candidate_labels.append("PHISHING")
    if text_analysis:
        candidate_labels.append(text_analysis["label"])
    for la in link_analyses:
        candidate_labels.append(la["label"])

    label_priority = {"LEGITIME": 0, "SUSPECT": 1, "PHISHING": 2}
    overall_label = "LEGITIME"
    for lbl in candidate_labels:
        if label_priority.get(lbl, 0) > label_priority.get(overall_label, 0):
            overall_label = lbl

    result = {
        "filename": filename,
        "filename_suspicious": filename_suspicious,
        "filename_reasons": filename_reasons,
        "is_pdf": is_pdf,
        "pdf_parse_error": pdf_parse_error,
        "structure_label": structure_label,
        "structure_reasons": structure_reasons,
        "is_office_doc": is_office_doc,
        "has_macros": has_macros,
        "macro_label": macro_label,
        "macro_reasons": macro_reasons,
        "is_zip": is_zip_signature,
        "zip_label": zip_label,
        "zip_reasons": zip_reasons,
        "is_lnk": is_lnk,
        "lnk_label": lnk_label,
        "lnk_reasons": lnk_reasons,
        "is_7z": is_7z,
        "sevenz_label": sevenz_label,
        "sevenz_reasons": sevenz_reasons,
        "is_tar": is_tar,
        "tar_label": tar_label,
        "tar_reasons": tar_reasons,
        "virustotal": vt_result,
        "vt_label": vt_label,
        "vt_reasons": vt_reasons,
        "extracted_text_excerpt": extracted_text[:500],
        "text_analysis": text_analysis,
        "links_found": links_found,
        "link_analyses": link_analyses,
        "overall_label": overall_label,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return jsonify(result)


@app.route("/api/analyze-page", methods=["POST"])
@api_key_or_login_required
def api_analyze_page():
    """Analyse continue d'une page web en cours de navigation (pas un simple lien
    clique) : combine l'analyse texte/URL habituelle avec des signaux structurels
    (champ mot de passe, champ OTP/PIN) que seul le navigateur peut observer.
    Concu pour etre appele plusieurs fois pendant qu'un utilisateur navigue sur
    un meme site, afin de detecter une attaque qui se revele progressivement
    (le formulaire de phishing n'apparait parfois qu'apres plusieurs clics)."""
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    visible_text = (data.get("visible_text") or "")[:5000]
    has_password_field = bool(data.get("has_password_field"))
    has_otp_field = bool(data.get("has_otp_field"))
    has_phone_field = bool(data.get("has_phone_field"))

    if not url:
        return jsonify({"error": "url manquante"}), 400

    combined_text = f"{url}\n{visible_text}"
    result = analyzer.analyze(combined_text, channel="web-page")

    # Bonus structurels : un champ de mot de passe ou de code OTP sur une page
    # deja un minimum suspecte (typosquat, urgence...) est un signal fort et
    # tres specifique de phishing actif - c'est precisement ce qui permet au
    # score de grimper au fil de la navigation, meme si la premiere page visitee
    # semblait anodine.
    bonus = 0.0
    if has_password_field and result["score"] >= 0.20:
        bonus += 0.20
        result["reasons"].append("Formulaire de mot de passe detecte sur une page deja suspecte")
    if has_otp_field:
        bonus += 0.30
        result["reasons"].append("Champ de code OTP/PIN detecte sur la page — signe tres specifique de phishing Mobile Money")
    if has_phone_field and result["score"] >= 0.20:
        bonus += 0.15
        result["reasons"].append("Champ de collecte de numero de telephone detecte sur une page deja suspecte")

    final_score = round(min(result["score"] + bonus, 1.0), 2)
    result["score"] = final_score
    if final_score >= 0.55:
        result["label"] = "PHISHING"
    elif final_score >= 0.30:
        result["label"] = "SUSPECT"
    else:
        result["label"] = "LEGITIME"

    result["sender"] = url
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    analysis_id = save_analysis(result, user_id=resolve_current_user_id())
    result["id"] = analysis_id
    return jsonify(result)


DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".apk",
                        ".jar", ".msi", ".ps1", ".com", ".pif", ".hta"]


def analyze_email_headers(msg):
    """Detecte les incoherences d'en-tetes typiques du phishing par usurpation."""
    reasons = []
    score = 0.0

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    def extract_domain_from_header(h):
        m = re.search(r"@([\w\.-]+)", h or "")
        return m.group(1).lower() if m else None

    from_domain = extract_domain_from_header(from_header)
    reply_domain = extract_domain_from_header(reply_to)
    return_domain = extract_domain_from_header(return_path)

    if reply_domain and from_domain and reply_domain != from_domain:
        score += 0.25
        reasons.append(
            f"Incoherence d'en-tete : 'Repondre a' ({reply_domain}) different de l'expediteur affiche ({from_domain})"
        )

    if return_domain and from_domain and return_domain != from_domain:
        score += 0.15
        reasons.append(
            f"Incoherence d'en-tete : chemin de retour ({return_domain}) different de l'expediteur affiche ({from_domain})"
        )

    return score, reasons


def analyze_attachments(msg):
    """Signale les pieces jointes a extension dangereuse."""
    reasons = []
    score = 0.0
    if not msg.is_multipart():
        return score, reasons

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        lower = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if lower.endswith(ext):
                score += 0.35
                reasons.append(f"Piece jointe a extension dangereuse detectee : {filename}")
                break

    return score, reasons


# ---------------------------------------------------------------------------
# Poller Email IMAP (automatique) - boucle sur TOUTES les boites que les
# utilisateurs ont connectees dans leurs reglages (table mailbox_connections),
# chacune analysee et rattachee a son propre proprietaire.
# ---------------------------------------------------------------------------
def get_all_mailbox_connections():
    with DB_LOCK:
        conn = get_db()
        rows = conn.execute("SELECT * FROM mailbox_connections").fetchall()
        conn.close()
    return rows


def poll_one_mailbox(connection, seen_uids_by_conn):
    conn_id = connection["id"]
    user_id = connection["user_id"]
    host = connection["imap_host"]
    user = connection["imap_user"]
    password = decrypt_secret(connection["imap_password_enc"])
    if password is None:
        print(f"[IMAP] Connexion #{conn_id} : mot de passe illisible (SECRET_KEY a change ?), ignoree.")
        return

    try:
        mail = imaplib.IMAP4_SSL(host)
        mail.login(user, password)
        mail.select("inbox")
        status, data = mail.search(None, "UNSEEN")
        for num in data[0].split():
            status, msg_data = mail.fetch(num, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            subject, encoding = decode_header(msg["Subject"])[0] if msg["Subject"] else ("", None)
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8", errors="ignore")

            sender = msg.get("From", "inconnu")

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode(errors="ignore")
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            full_text = f"{subject}\n{body}".strip()
            result = analyzer.analyze(full_text, channel="email")
            result["sender"] = sender
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            header_score, header_reasons = analyze_email_headers(msg)
            attach_score, attach_reasons = analyze_attachments(msg)
            if header_reasons or attach_reasons:
                result["reasons"].extend(header_reasons)
                result["reasons"].extend(attach_reasons)
                result["score"] = round(min(result["score"] + header_score + attach_score, 1.0), 2)
                if result["score"] >= 0.55:
                    result["label"] = "PHISHING"
                elif result["score"] >= 0.30:
                    result["label"] = "SUSPECT"

            reputation = get_sender_reputation(sender)
            if reputation["repeat_offender"]:
                result["reasons"].append(
                    f"Expediteur recidiviste : deja flagge {reputation['phishing_count']}/{reputation['total_count']} fois"
                )
            save_analysis(result, user_id=user_id)
            print(f"[IMAP] ({user}) Nouveau mail analyse: {result['label']} ({result['score']}) - {sender}")

        mail.logout()
    except Exception as e:
        print(f"[IMAP] Erreur sur la boite {user} (connexion #{conn_id}): {e}")


def imap_poll_loop():
    print("[IMAP] Poller multi-boites demarre - verifie mailbox_connections toutes les 20s.")
    while True:
        connections = get_all_mailbox_connections()
        if not connections:
            time.sleep(20)
            continue
        for connection in connections:
            poll_one_mailbox(connection, None)
        # Intervalle base sur la connexion la plus exigeante, borne a 10s minimum
        min_interval = min((c["poll_seconds"] or 20) for c in connections)
        time.sleep(max(min_interval, 10))


# ---------------------------------------------------------------------------
# Demarrage du poller IMAP en arriere-plan.
# Fait au niveau module (pas seulement dans __main__) pour fonctionner a la fois :
# - en local avec `python app.py`
# - en production avec un serveur WSGI comme gunicorn, qui importe ce module
#   sans jamais executer le bloc __main__.
# Garde-fou _IMAP_THREAD_STARTED pour eviter un double-demarrage si le module
# est importe plusieurs fois (rare, mais gunicorn avec plusieurs workers peut
# le faire : dans ce cas, lancer gunicorn avec --workers 1).
# ---------------------------------------------------------------------------
_IMAP_THREAD_STARTED = False


def _start_background_threads():
    global _IMAP_THREAD_STARTED
    if _IMAP_THREAD_STARTED:
        return
    _IMAP_THREAD_STARTED = True
    t = threading.Thread(target=imap_poll_loop, daemon=True)
    t.start()


_start_background_threads()


if __name__ == "__main__":
    # Lancement local de dev. En production (Railway), c'est gunicorn qui sert
    # l'app via le Procfile - ce bloc n'est alors jamais execute.
    # Railway fournit l'adresse d'ecoute via la variable d'environnement PORT.
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    print(f"[PhishGuard] Demarrage en local sur le port {port} (HTTP, pas de certificat necessaire)")
    app.run(host="0.0.0.0", port=port, debug=debug_mode, use_reloader=False)
