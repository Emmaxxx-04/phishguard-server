"""
Moteur d'analyse phishing : combine des regles explicables (heuristiques),
un module de forensic URL/domaine (typosquatting, punycode, etc.)
et un classifieur TF-IDF + Regression Logistique explicable.
"""
import re
import os
import pickle
import numpy as np

from urlintel import analyze_urls

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# --- Mots-cles et patterns suspects (contexte Togo / Mobile Money / francophone) ---
URGENCY_WORDS = [
    "urgent", "immediatement", "immediat", "dans 24h", "dans les 24 heures",
    "expire", "expiration", "derniere notification", "action requise",
    "sans delai", "des maintenant", "avant expiration", "bloque", "bloquee",
    "suspendu", "suspendue", "ferme dans",
]

CREDENTIAL_REQUEST_WORDS = [
    "code pin", "code secret", "code otp", "coordonnees bancaires",
    "numero de carte", "cvv", "code flooz", "informations bancaires",
]

# Patterns contextuels : "mot de passe"/"identifiant" ne sont suspects que combines
# a un verbe d'action (entrer, confirmer...), pas en simple mention ("ton mot de passe habituel")
CREDENTIAL_ACTION_PATTERN = re.compile(
    r"(entrez|entrer|confirmez|confirmer|saisissez|saisir|donnez|donner|"
    r"communiquez|communiquer|renseignez|renseigner).{0,20}(mot de passe|identifiant)",
    re.IGNORECASE,
)

REWARD_SCAM_WORDS = [
    "felicitations", "vous avez gagne", "gagnant", "tirage", "pret sans garantie",
    "vous avez ete selectionne", "reclamer votre gain",
]

BUSINESS_SCAM_WORDS = [
    "virement urgent", "confidentiel", "caution", "facture impayee",
    "nouveau compte", "avant 17h", "ne pas en parler", "arriere d'impot",
    "frais de douane", "salaire de",
]

SUSPICIOUS_LINK_PATTERNS = [
    r"bit\.ly", r"tinyurl", r"\.tk\b", r"\.xyz\b", r"\.info\b",
    r"secure-?login", r"verif(y|ication)?[-_]?account", r"update[-_]?account",
    r"-secure-", r"tax\.net", r"regularisation",
]

GENERIC_GREETING = ["cher client", "cher(e) utilisateur", "cher abonne", "cher(e) client"]


def rule_based_score(text: str):
    t = text.lower()
    reasons = []
    score = 0.0

    for w in URGENCY_WORDS:
        if w in t:
            # "action requise" precede d'une negation (aucune/pas/sans) = pas suspect
            if w == "action requise" and re.search(r"(aucune|pas d[e']|sans)\s+action\s+requise", t):
                continue
            score += 0.15
            reasons.append(f"Langage d'urgence detecte (\"{w}\")")
            break

    for w in CREDENTIAL_REQUEST_WORDS:
        if w in t:
            score += 0.30
            reasons.append(f"Demande d'information sensible (\"{w}\")")
            break

    if CREDENTIAL_ACTION_PATTERN.search(t):
        score += 0.30
        reasons.append("Demande explicite de saisir un mot de passe/identifiant")

    for w in REWARD_SCAM_WORDS:
        if w in t:
            score += 0.20
            reasons.append(f"Promesse de gain suspecte (\"{w}\")")
            break

    for w in BUSINESS_SCAM_WORDS:
        if w in t:
            score += 0.20
            reasons.append(f"Formulation typique d'arnaque professionnelle (\"{w}\")")
            break

    for pat in SUSPICIOUS_LINK_PATTERNS:
        if re.search(pat, t):
            score += 0.25
            reasons.append(f"Lien/domaine suspect (motif: {pat})")
            break

    for w in GENERIC_GREETING:
        if w in t:
            score += 0.05
            reasons.append("Formule de salutation generique (non personnalisee)")
            break

    if re.search(r"https?://[^\s]+", t) and ("compte" in t or "verif" in t or "connexion" in t):
        score += 0.10
        reasons.append("Lien combine a une demande liee au compte")

    return min(score, 1.0), reasons


class PhishingAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                data = pickle.load(f)
                self.model = data["model"]
                self.vectorizer = data["vectorizer"]

    FRENCH_STOPWORDS = {
        "le", "la", "les", "de", "du", "des", "un", "une", "et", "est", "ou", "où",
        "dans", "pour", "sur", "avec", "ce", "ces", "cette", "son", "sa", "ses",
        "que", "qui", "ne", "pas", "vous", "nous", "il", "elle", "se", "au", "aux",
        "en", "par", "plus", "tout", "tous", "http", "com", "www",
    }

    def _top_contributing_words(self, text: str, top_n: int = 3):
        """Retourne les mots/bi-grammes du texte qui ont le plus pousse le score ML vers 'phishing'."""
        if self.model is None or self.vectorizer is None:
            return []
        X = self.vectorizer.transform([text])
        coefs = self.model.coef_[0]
        feature_names = self.vectorizer.get_feature_names_out()
        nonzero_idx = X.nonzero()[1]
        if len(nonzero_idx) == 0:
            return []
        contributions = [(feature_names[i], X[0, i] * coefs[i]) for i in nonzero_idx]
        contributions.sort(key=lambda x: x[1], reverse=True)
        top_terms = []
        for term, weight in contributions:
            if weight <= 0:
                continue
            words_in_term = term.split()
            if all(w in self.FRENCH_STOPWORDS or len(w) <= 2 for w in words_in_term):
                continue
            top_terms.append(term)
            if len(top_terms) == top_n:
                break
        return top_terms

    def analyze(self, text: str, channel: str = "email"):
        rule_score, reasons = rule_based_score(text)

        url_score, url_reasons, domains = analyze_urls(text)
        rule_score = min(rule_score + url_score, 1.0)
        reasons.extend(url_reasons)

        ml_score = None
        if self.model is not None:
            X = self.vectorizer.transform([text])
            proba = self.model.predict_proba(X)[0]
            ml_score = float(proba[1])

        if ml_score is not None:
            final_score = 0.5 * rule_score + 0.5 * ml_score
            if ml_score >= 0.45:
                top_words = self._top_contributing_words(text)
                if top_words:
                    reasons.append(f"Modele ML — mots les plus suspects: {', '.join(top_words)} (score: {ml_score:.2f})")
                else:
                    reasons.append(f"Score du modele ML (TF-IDF): {ml_score:.2f}")
        else:
            final_score = rule_score

        if final_score >= 0.55:
            label = "PHISHING"
        elif final_score >= 0.30:
            label = "SUSPECT"
        else:
            label = "LEGITIME"

        if not reasons:
            reasons.append("Aucun indicateur de risque detecte")

        return {
            "channel": channel,
            "text": text,
            "score": round(final_score, 2),
            "label": label,
            "reasons": reasons,
            "domains": domains,
        }
