"""
PhishGuard Togo - Detection automatique de phishing (email + SMS/autres canaux)
Lancement: python3 app.py
"""
import os
import re
import threading
import time
import secrets
import base64
import hashlib
import imaplib
import email
from email.header import decode_header
from datetime import datetime
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

from analyzer import PhishingAnalyzer
from threat_intel import check_virustotal, check_urlscan

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
# Couche base de donnees : Postgres (Neon), avec une petite compatibilite qui
# garde la meme facon d'ecrire le code partout ailleurs dans ce fichier
# (conn.execute(...) -> objet avec .fetchone()/.fetchall(), acces aux colonnes
# par nom via row["colonne"], .lastrowid apres un INSERT ... RETURNING id).
# Auparavant sur SQLite (fichier local) : perdait toutes les donnees a chaque
# redemarrage/redeploiement sur l'hebergement gratuit -> Postgres externe
# (Neon, gratuit et persistant) regle definitivement ce probleme.
# =============================================================================
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL manquante. Definis cette variable d'environnement avec "
        "ta chaine de connexion Postgres (ex: fournie par Neon), au format "
        "postgresql://utilisateur:motdepasse@hote/nom_base"
    )

DB_LOCK = threading.Lock()


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
    pg_conn = psycopg2.connect(DATABASE_URL)
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
        return None
    with DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT id FROM users WHERE api_key = ?", (api_key,)).fetchone()
        conn.close()
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
        conn.close()
        if row and row["total_count"] > 1 and row["phishing_count"] >= 1:
            return {"repeat_offender": True, "phishing_count": row["phishing_count"], "total_count": row["total_count"]}
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
        conn.close()

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

    with DB_LOCK:
        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email_addr,)).fetchone()
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
        conn.close()

    session["user_id"] = user_id
    session["user_email"] = email_addr
    session["user_name"] = display_name or email_addr.split("@")[0]
    return redirect(url_for("dashboard"))


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
    return render_template("settings.html", user=user, mailbox=mailbox, error=None, saved=False)


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
                                error="Hote, email et mot de passe requis.", saved=False), 400

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
    return render_template("check_url.html")


@app.route("/security-checkup")
def security_checkup_page():
    return render_template("security_checkup.html")


@app.route("/check-qr")
def check_qr_page():
    return render_template("check_qr.html")


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
    """Permet de corriger une analyse (faux positif/negatif) - alimente l'amelioration continue.
    Restreint aux analyses appartenant a l'utilisateur connecte."""
    data = request.get_json(force=True)
    analysis_id = data.get("id")
    corrected_label = data.get("label")
    if not analysis_id or corrected_label not in ("PHISHING", "SUSPECT", "LEGITIME"):
        return jsonify({"error": "parametres invalides"}), 400

    with DB_LOCK:
        conn = get_db()
        owner = conn.execute("SELECT user_id FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if not owner or owner["user_id"] != session["user_id"]:
            conn.close()
            return jsonify({"error": "analyse introuvable"}), 404

        conn.execute(
            "UPDATE analyses SET corrected_label = ? WHERE id = ?",
            (corrected_label, analysis_id)
        )
        conn.commit()

        # Ajoute cet exemple corrige au jeu de donnees pour un futur re-entrainement
        row = conn.execute("SELECT text FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        conn.close()

    if row:
        label_int = 1 if corrected_label in ("PHISHING", "SUSPECT") else 0
        text_escaped = row["text"].replace('"', '""')
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

    result = analyzer.analyze(text, channel=channel)
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
