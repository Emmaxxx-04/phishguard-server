"""
PhishGuard Togo - Detection automatique de phishing (email + SMS/autres canaux)
Lancement: python3 app.py
"""
import os
import threading
import time
import sqlite3
import imaplib
import email
from email.header import decode_header
from datetime import datetime

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

from analyzer import PhishingAnalyzer

load_dotenv()

app = Flask(__name__)
CORS(app)  # autorise l'extension Chrome (chrome-extension://...) a appeler l'API locale
analyzer = PhishingAnalyzer()

DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")
DB_LOCK = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with DB_LOCK:
        conn = get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                sender TEXT,
                analysis_id INTEGER,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()


init_db()


def save_analysis(result):
    with DB_LOCK:
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO analyses (channel, sender, text, score, label, reasons, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (result["channel"], result.get("sender", "inconnu"), result["text"],
             result["score"], result["label"], "|||".join(result["reasons"]),
             result["timestamp"])
        )
        analysis_id = cur.lastrowid

        sender = result.get("sender", "inconnu")
        is_threat = 1 if result["label"] in ("PHISHING", "SUSPECT") else 0
        conn.execute("""
            INSERT INTO sender_reputation (sender, phishing_count, total_count)
            VALUES (?, ?, 1)
            ON CONFLICT(sender) DO UPDATE SET
                phishing_count = phishing_count + ?,
                total_count = total_count + 1
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
        rows = conn.execute("""
            SELECT domain, COUNT(DISTINCT sender) as sender_count, COUNT(*) as occurrences,
                   MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
            FROM domain_sightings
            GROUP BY domain
            ORDER BY occurrences DESC
        """).fetchall()
        conn.close()

    all_domains = [dict(r) for r in rows]

    from urlintel import levenshtein

    # Union simple : regroupe les domaines dont la racine est a distance <= 2
    clusters = []
    used = [False] * len(all_domains)
    for i, d in enumerate(all_domains):
        if used[i]:
            continue
        cluster = [d]
        used[i] = True
        base_i = d["domain"].split(".")[0]
        for j in range(i + 1, len(all_domains)):
            if used[j]:
                continue
            base_j = all_domains[j]["domain"].split(".")[0]
            if levenshtein(base_i, base_j) <= 2:
                cluster.append(all_domains[j])
                used[j] = True
        clusters.append(cluster)

    campaigns = []
    for cluster in clusters:
        total_senders = sum(c["sender_count"] for c in cluster)
        total_occurrences = sum(c["occurrences"] for c in cluster)
        if total_senders < 2 and total_occurrences < 2:
            continue
        campaigns.append({
            "domain": " / ".join(c["domain"] for c in cluster),
            "sender_count": total_senders,
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


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/outlook-addin/<path:filename>")
def outlook_addin_files(filename):
    addin_dir = os.path.join(os.path.dirname(__file__), "outlook-addin")
    return send_from_directory(addin_dir, filename)


@app.route("/api/feed")
def api_feed():
    with DB_LOCK:
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT 50"
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
    return jsonify(feed)


@app.route("/api/stats")
def api_stats():
    with DB_LOCK:
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) c FROM analyses").fetchone()["c"]
        threats = conn.execute(
            "SELECT COUNT(*) c FROM analyses WHERE label IN ('PHISHING','SUSPECT')"
        ).fetchone()["c"]
        by_channel = conn.execute(
            "SELECT channel, COUNT(*) c FROM analyses GROUP BY channel"
        ).fetchall()
        repeat_offenders = conn.execute(
            "SELECT COUNT(*) c FROM sender_reputation WHERE phishing_count >= 1 AND total_count > 1"
        ).fetchone()["c"]
        corrections = conn.execute(
            "SELECT COUNT(*) c FROM analyses WHERE corrected_label IS NOT NULL"
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


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    """Permet de corriger une analyse (faux positif/negatif) - alimente l'amelioration continue."""
    data = request.get_json(force=True)
    analysis_id = data.get("id")
    corrected_label = data.get("label")
    if not analysis_id or corrected_label not in ("PHISHING", "SUSPECT", "LEGITIME"):
        return jsonify({"error": "parametres invalides"}), 400

    with DB_LOCK:
        conn = get_db()
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
def api_analyze():
    """Point d'entree generique : email, SMS simule, ou autre canal futur."""
    data = request.get_json(force=True)
    text = data.get("text", "")
    channel = data.get("channel", "sms")
    sender = data.get("sender", "inconnu")

    if not text.strip():
        return jsonify({"error": "texte vide"}), 400

    result = analyzer.analyze(text, channel=channel)
    result["sender"] = sender
    result["timestamp"] = datetime.now().strftime("%H:%M:%S")

    reputation = get_sender_reputation(sender)
    if reputation["repeat_offender"]:
        result["reasons"].append(
            f"Expediteur recidiviste : deja flagge {reputation['phishing_count']}/{reputation['total_count']} fois"
        )

    analysis_id = save_analysis(result)
    result["id"] = analysis_id
    result["reputation"] = reputation
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
# Poller Email IMAP (automatique) - tourne en arriere-plan si configure
# ---------------------------------------------------------------------------
def imap_poll_loop():
    host = os.getenv("IMAP_HOST")
    user = os.getenv("IMAP_USER")
    password = os.getenv("IMAP_PASSWORD")
    interval = int(os.getenv("IMAP_POLL_SECONDS", "20"))

    if not (host and user and password):
        print("[IMAP] Non configure (.env manquant) - poller email desactive.")
        return

    seen_uids = set()
    print(f"[IMAP] Poller demarre sur {user} (toutes les {interval}s)")

    while True:
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
                result["timestamp"] = datetime.now().strftime("%H:%M:%S")

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
                save_analysis(result)
                print(f"[IMAP] Nouveau mail analyse: {result['label']} ({result['score']}) - {sender}")

            mail.logout()
        except Exception as e:
            print(f"[IMAP] Erreur poller: {e}")

        time.sleep(interval)


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
