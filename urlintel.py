"""
Module de forensic URL/domaine pour la detection de phishing.
Techniques: typosquatting (distance d'edition), homographes/punycode,
TLD suspects, IP litterale, raccourcisseurs d'URL, sous-domaines excessifs.
"""
import re
import math
from urllib.parse import urlparse

# Marques legitimes cibles frequentes de phishing au Togo / en Afrique de l'Ouest
KNOWN_BRANDS = {
    "tmoney": ["tmoney.tg"],
    "flooz": ["moov-africa.tg", "flooz.tg"],
    "ecobank": ["ecobank.com"],
    "uba": ["ubagroup.com", "uba.tg"],
    "orabank": ["orabank.net"],
    "togocom": ["togocom.tg"],
    "moov": ["moov-africa.tg"],
    "brvm": ["brvm.org"],
    "whatsapp": ["whatsapp.com"],
    "gmail": ["gmail.com", "google.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "paypal": ["paypal.com"],
}

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".info",
                    ".click", ".link", ".work", ".loan", ".win", ".buzz", ".cyou",
                    ".surf", ".rest", ".cfd", ".sbs", ".icu", ".mom"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
                   "buff.ly", "cutt.ly", "shorturl.at"]

URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
BARE_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:tk|ml|ga|cf|gq|xyz|top|info|click|link|work|loan|win|"
    r"com|net|org|tg|ly|co|io|app|site)\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)


def levenshtein(a: str, b: str) -> int:
    """Distance d'edition classique (DP), sans dependance externe."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[lb]


def extract_urls(text: str):
    with_protocol = URL_REGEX.findall(text)
    covered_spans = set()
    for u in with_protocol:
        covered_spans.add(u)

    bare = BARE_DOMAIN_REGEX.findall(text)
    # findall avec groupes retourne parfois des tuples ; on reconstruit via finditer pour le texte complet
    bare_matches = [m.group(0) for m in BARE_DOMAIN_REGEX.finditer(text)]

    results = list(with_protocol)
    for b in bare_matches:
        # ignore si deja capture comme partie d'une URL avec protocole
        if any(b in u for u in with_protocol):
            continue
        results.append("http://" + b)  # normalise pour le parsing en aval
    return results


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().split(":")[0]
    except Exception:
        return ""


def is_ip_literal(domain: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))


def is_punycode(domain: str) -> bool:
    return "xn--" in domain


def check_typosquatting(domain: str):
    """Compare le domaine aux marques connues. Retourne (marque_ciblee, distance) si suspect."""
    domain_clean = domain.replace("www.", "")
    base = domain_clean.split(".")[0]  # partie avant le premier point

    for brand, official_domains in KNOWN_BRANDS.items():
        if domain_clean in official_domains:
            continue  # domaine officiel, rien a signaler
        dist = levenshtein(base, brand)
        # Distance courte = tres proche du nom de marque mais pas exact -> typosquatting probable
        if 0 < dist <= 2 and len(brand) > 3:
            return brand, dist
        # Le nom de la marque est contenu dans un domaine plus long et suspect (ex: tmoney-secure-verif.com)
        if brand in domain_clean and domain_clean not in official_domains:
            return brand, 0
    return None, None


# Liste blanche de securite : grandes plateformes mondiales + institutions locales,
# jamais soumises a la detection generique "domaine aleatoire" pour eviter tout faux positif.
ALLOWLIST_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "facebook.com", "whatsapp.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "office.com", "live.com", "amazon.com", "github.com", "wikipedia.org",
    "apple.com", "paypal.com", "netflix.com", "spotify.com", "tiktok.com",
    "togocom.tg", "ecobank.com", "ubagroup.com", "uba.tg", "tmoney.tg",
    "flooz.tg", "moov-africa.tg", "brvm.org", "orabank.net", "yahoo.com",
    "outlook.com", "chatgpt.com", "openai.com", "anthropic.com", "claude.ai",
}


def is_allowlisted_domain(domain: str) -> bool:
    d = domain.replace("www.", "")
    return any(d == allowed or d.endswith("." + allowed) for allowed in ALLOWLIST_DOMAINS)


def looks_randomly_generated(label: str) -> bool:
    """Heuristique conservatrice : les vrais mots/marques ont des voyelles et peu
    de chiffres. Une chaine sans voyelle ou tres riche en chiffres ressemble
    davantage a un identifiant genere automatiquement qu'a un nom de domaine reel."""
    if len(label) < 6:
        return False  # trop court pour juger de maniere fiable, on evite le faux positif
    vowels = set("aeiou")
    vowel_count = sum(1 for c in label if c in vowels)
    digit_count = sum(1 for c in label if c.isdigit())
    vowel_ratio = vowel_count / len(label)
    digit_ratio = digit_count / len(label)

    if vowel_ratio < 0.15:
        return True
    if digit_ratio > 0.3 and vowel_ratio < 0.25:
        return True
    return False


def analyze_urls(text: str):
    """Analyse toutes les URLs d'un texte. Retourne (score_ajout, reasons, domains_extraits)."""
    urls = extract_urls(text)
    if not urls:
        return 0.0, [], []

    score = 0.0
    reasons = []
    domains = []

    for url in urls:
        domain = extract_domain(url)
        if not domain:
            continue
        domains.append(domain)

        if is_ip_literal(domain):
            score += 0.30
            reasons.append(f"Lien pointant vers une adresse IP brute ({domain}) au lieu d'un nom de domaine")

        if is_punycode(domain):
            score += 0.30
            reasons.append(f"Domaine encode en punycode (technique d'homographe): {domain}")

        for shortener in URL_SHORTENERS:
            d = domain.replace("www.", "")
            if d == shortener or d.endswith("." + shortener):
                score += 0.15
                reasons.append(f"Raccourcisseur d'URL detecte ({shortener}) — destination masquee")
                break

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 0.15
                reasons.append(f"Extension de domaine a risque ({tld}): {domain}")
                break

        subdomain_count = domain.count(".")
        if subdomain_count >= 3 and not is_ip_literal(domain):
            score += 0.10
            reasons.append(f"Nombre inhabituel de sous-domaines ({domain})")

        brand, dist = check_typosquatting(domain)
        if brand:
            if dist == 0:
                score += 0.35
                reasons.append(f"Imite le nom de la marque '{brand}' dans un domaine non-officiel: {domain}")
            else:
                score += 0.30
                reasons.append(f"Typosquatting probable de '{brand}' (distance d'edition {dist}): {domain}")

        # Detection generique de domaines a l'aspect genere aleatoirement,
        # pour les liens qui n'imitent aucune marque connue mais restent louches.
        if not is_allowlisted_domain(domain) and not is_ip_literal(domain):
            label = domain.replace("www.", "").split(".")[0]
            if looks_randomly_generated(label):
                score += 0.20
                reasons.append(f"Nom de domaine a l'aspect genere aleatoirement ({label}) — signe frequent de site jetable/malveillant")

    return min(score, 1.0), reasons, domains
