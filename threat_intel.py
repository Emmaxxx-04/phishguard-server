"""
Module d'enrichissement via des sources de threat intelligence externes.
Actuellement : VirusTotal (reputation de domaines/URLs via ~70 moteurs antivirus).

Design volontairement defensif : ce module ne doit JAMAIS faire planter l'app
principale. Toute erreur reseau, timeout, ou absence de cle API renvoie un
resultat "indisponible" propre plutot que de lever une exception.

Utilise a la demande (bouton "Verifier aussi sur VirusTotal"), jamais dans le
flux d'analyse automatique principal - le tier gratuit VirusTotal est limite
a 4 requetes/minute, incompatible avec une analyse automatique de chaque
email/SMS recu.
"""
import os
import time
import base64
import requests

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
TIMEOUT_SECONDS = 8


def _url_to_vt_id(url: str) -> str:
    """VirusTotal identifie une URL par son SHA256... en pratique l'API v3
    accepte aussi l'identifiant base64url (sans padding) de l'URL elle-meme."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal(url: str):
    """Interroge VirusTotal pour une URL donnee.

    Retourne un dict :
    {
        "available": bool,       # False si cle API absente ou service injoignable
        "found": bool,           # True si VirusTotal connait deja cette URL
        "malicious": int,        # nombre de moteurs la jugeant malveillante
        "suspicious": int,
        "harmless": int,
        "total_engines": int,
        "message": str,          # message a afficher a l'utilisateur
    }
    """
    if not VT_API_KEY:
        return {
            "available": False, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": "Cle API VirusTotal non configuree sur ce serveur.",
        }

    headers = {"x-apikey": VT_API_KEY}
    url_id = _url_to_vt_id(url)

    try:
        res = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as e:
        return {
            "available": False, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": f"VirusTotal injoignable pour le moment ({type(e).__name__}).",
        }

    if res.status_code == 404:
        return {
            "available": True, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": "URL inconnue de VirusTotal (jamais signalee ou analysee) — "
                       "notre propre moteur reste la source principale pour ce lien.",
        }

    if res.status_code == 401:
        return {
            "available": False, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": "Cle API VirusTotal invalide.",
        }

    if res.status_code != 200:
        return {
            "available": False, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": f"VirusTotal a repondu de maniere inattendue (code {res.status_code}).",
        }

    try:
        data = res.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            message = f"{malicious} moteur(s) antivirus sur {total} classent ce lien comme malveillant."
        elif suspicious > 0:
            message = f"{suspicious} moteur(s) antivirus sur {total} le jugent suspect."
        else:
            message = f"Aucun des {total} moteurs antivirus consultes ne signale ce lien."

        return {
            "available": True, "found": True,
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "total_engines": total,
            "message": message,
        }
    except (KeyError, ValueError) as e:
        return {
            "available": False, "found": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "total_engines": 0,
            "message": "Reponse VirusTotal illisible (format inattendu).",
        }


def check_urlscan(url: str):
    """Soumet une URL a URLScan.io pour capture d'ecran + analyse visuelle.

    Contrairement a VirusTotal, un scan URLScan prend reellement du temps
    (le site est visite en direct dans un navigateur virtuel). On tente un
    court sondage (quelques secondes max) pour recuperer le resultat tout de
    suite si possible, mais on fournit TOUJOURS un lien vers la page de
    resultat complete en repli - jamais de blocage indefini.

    Retourne un dict :
    {
        "available": bool,
        "ready": bool,              # True si le scan est deja termine
        "screenshot_url": str|None,
        "result_page_url": str|None,
        "message": str,
    }
    """
    if not URLSCAN_API_KEY:
        return {
            "available": False, "ready": False,
            "screenshot_url": None, "result_page_url": None,
            "message": "Cle API URLScan non configuree sur ce serveur.",
        }

    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

    try:
        submit_res = requests.post(
            f"{URLSCAN_BASE_URL}/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as e:
        return {
            "available": False, "ready": False,
            "screenshot_url": None, "result_page_url": None,
            "message": f"URLScan injoignable pour le moment ({type(e).__name__}).",
        }

    if submit_res.status_code == 401:
        return {
            "available": False, "ready": False,
            "screenshot_url": None, "result_page_url": None,
            "message": "Cle API URLScan invalide.",
        }

    if submit_res.status_code not in (200, 201):
        return {
            "available": False, "ready": False,
            "screenshot_url": None, "result_page_url": None,
            "message": f"URLScan a refuse la soumission (code {submit_res.status_code}).",
        }

    try:
        submit_data = submit_res.json()
        uuid = submit_data["uuid"]
        result_page_url = submit_data.get("result", f"https://urlscan.io/result/{uuid}/")
        screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
        api_url = submit_data.get("api", f"{URLSCAN_BASE_URL}/result/{uuid}/")
    except (KeyError, ValueError):
        return {
            "available": False, "ready": False,
            "screenshot_url": None, "result_page_url": None,
            "message": "Reponse URLScan illisible a la soumission.",
        }

    # Sondage court : on attend que le scan se termine, sans jamais depasser
    # un budget de temps raisonnable pour rester compatible avec une demo live.
    max_attempts = 4
    wait_seconds = 3
    for attempt in range(max_attempts):
        time.sleep(wait_seconds)
        try:
            poll_res = requests.get(api_url, timeout=TIMEOUT_SECONDS)
        except requests.exceptions.RequestException:
            break  # on sort de la boucle, le lien de repli reste valable

        if poll_res.status_code == 200:
            return {
                "available": True, "ready": True,
                "screenshot_url": screenshot_url,
                "result_page_url": result_page_url,
                "message": "Capture d'ecran et analyse disponibles.",
            }
        # 404 = scan toujours en cours, on reessaie

    # Scan pas encore termine apres le sondage : on donne quand meme le lien,
    # le resultat sera visible en cliquant dessus dans quelques instants.
    return {
        "available": True, "ready": False,
        "screenshot_url": None,
        "result_page_url": result_page_url,
        "message": "Scan lance, encore en cours de traitement — le resultat complet "
                   "sera disponible dans quelques instants via le lien ci-dessous.",
    }
