# FishGuard Mobile — MVP Android

## Distribuer l'app à ton équipe sans Android Studio

J'ai ajouté un pipeline GitHub Actions (`.github/workflows/build-apk.yml`) qui
compile automatiquement un `.apk` installable à chaque mise à jour du projet.
Tes coéquipiers n'ont besoin que d'un téléphone Android — pas d'Android Studio.

**Mise en place (une seule fois) :**

1. Crée un **dépôt privé** sur GitHub.
2. Depuis ce dossier, pousse le projet :
   ```bash
   git init
   git add .
   git commit -m "FishGuard mobile"
   git branch -M main
   git remote add origin https://github.com/<ton-compte>/<ton-repo>.git
   git push -u origin main
   ```
3. **Ajoute tes coéquipiers comme collaborateurs** (obligatoire pour un dépôt
   privé, sinon le lien de téléchargement leur demandera de se connecter sans
   succès) : sur GitHub → onglet **Settings** du dépôt → **Collaborators** →
   **Add people** → entre leur nom d'utilisateur ou email GitHub. Ils doivent
   accepter l'invitation (email ou notification GitHub) pour avoir accès.
4. Va dans l'onglet **Actions** du dépôt : le build se déclenche
   automatiquement (~5-10 minutes). S'il ne se lance pas tout seul, clique sur
   le workflow "Build FishGuard APK" puis **"Run workflow"**.
5. Une fois terminé (coche verte) : onglet **Releases** du dépôt → l'APK est
   attaché → copie le lien de téléchargement direct du fichier `.apk` (clic
   droit sur le fichier → "Copier l'adresse du lien") et partage-le dans votre
   groupe.

**Pour tes coéquipiers :** ils doivent être **connectés à leur compte GitHub**
(dans le navigateur du téléphone, ou via l'app GitHub) avant d'ouvrir le lien —
sinon le téléchargement d'un fichier de release privé échoue avec une erreur
403. Une fois connectés, ils cliquent le lien, téléchargent le `.apk`,
acceptent "Installer depuis une source inconnue" si demandé, et l'app
s'installe. Ils n'ouvrent jamais Android Studio.

**Important** : ce build est un APK de **debug**, parfait pour tester en
équipe, mais pas destiné à une publication sur le Play Store (il faudra alors
une vraie signature de release — je peux t'aider à mettre ça en place le
moment venu).

**Si un jour vous voulez zéro friction de connexion GitHub** (lien qui marche
pour n'importe qui sans compte) : deux options que je peux mettre en place —
rendre le dépôt public, ou passer par Firebase App Distribution (expérience
plus proche d'un app store, avec liens d'invitation dédiés aux testeurs).

**Si tu veux juste un APK une fois, sans mettre en place GitHub** : ouvre le
projet dans Android Studio sur ta machine une seule fois → menu **Build > Build
Bundle(s) / APK(s) > Build APK(s)** → le fichier apparaît dans
`app/build/outputs/apk/debug/` → partage-le directement (Drive, WhatsApp Web...).

---



## Corrections et nouveautés (dernière itération)

**Bugs corrigés :**
- **Impossible de scroller** : `SettingsScreen` et `OnboardingScreen` n'avaient
  aucun conteneur scrollable — corrigé avec `verticalScroll`. Un `Spacer(weight(1f))`
  dans l'onboarding provoquait en plus un crash potentiel une fois placé dans un
  conteneur scrollable (le poids vertical est invalide avec une hauteur infinie) —
  remplacé par un espacement fixe.
- **Notifications silencieuses** : le code d'alerte n'avait aucune gestion
  d'erreur — une exception (permission manquante, etc.) pouvait faire échouer
  l'analyse en arrière-plan silencieusement. Le tout est maintenant protégé par
  un `try/catch`, avec vérification explicite de la permission `POST_NOTIFICATIONS`
  avant d'appeler `notify()`. Un bouton **"Tester la notification"** a été ajouté
  dans Réglages pour vérifier en un clic que les alertes s'affichent bien.
- **Pas de bouton retour** : ajout d'une barre supérieure avec flèche de retour
  (`FishGuardTopBar`) sur les écrans empilés (détail d'une menace, test manuel).
  La barre de navigation du bas se masque automatiquement sur ces écrans.
- **Suppression accidentelle de l'historique** : le bouton "Effacer" agissait
  instantanément — une boîte de dialogue de confirmation a été ajoutée.

**Nouvelles fonctionnalités :**
- **Détection d'arnaques par appel téléphonique**, en deux volets — détaillés
  plus bas dans la section dédiée :
  - Avant de décrocher : vérification du numéro contre une liste locale de
    numéros signalés (`ScamCallScreeningService`).
  - Pendant l'appel : protection en direct, activable manuellement, avec
    transcription vocale hors ligne (Vosk) et score qui s'accumule en temps réel.
- Slogan de l'écran de démarrage : *"On ne mord plus à l'hameçon"*.
- Fond de l'icône adaptative aligné sur le fond sombre de l'app (au lieu du blanc).

- **Test manuel** : nouvel écran (bouton flottant sur le Dashboard) pour coller
  un message et voir instantanément le score, sans attendre de le recevoir
  réellement. Possibilité d'enregistrer le résultat dans l'historique.
- **Écran de démarrage animé** : logo qui apparaît avec un halo pulsé au lancement
  de l'app, avant d'arriver sur l'onboarding ou le dashboard.
- **Refonte visuelle du Dashboard** : bandeau d'en-tête en dégradé (couleurs de
  marque), cartes de statistiques repensées, bouton d'action flottant.
- **Backend enrichi** : en plus de l'URL, tu peux maintenant configurer le
  **chemin de l'endpoint** (si ton API n'utilise pas `/api/analyze`) et une
  **clé API optionnelle** (envoyée en header `Authorization: Bearer` et
  `X-API-Key`). Un bouton **"Tester"** vérifie la connexion sans quitter les réglages.

---



Application Android (Kotlin + Jetpack Compose) qui étend FishGuard au-delà des
emails : détection en temps réel des arnaques par **SMS** et **notifications WhatsApp**,
avec un moteur de règles taillé pour les schémas d'**usurpation d'identité** et
d'**avance de frais** ("je m'appelle X, envoie-moi 10 000, je te renverrai le triple").

## Nouveautés de cette itération

- **Vrai logo** : l'icône de l'app et le mark utilisé dans le dashboard/onboarding
  viennent directement du logo officiel (bouclier + hameçon + poisson), extrait et
  recadré depuis le PNG fourni. Icône adaptative propre (`res/mipmap-anydpi-v26`).
- **Palette bleue** reprise du logo, avec **thème clair/sombre/système** réglable
  dans Réglages > Apparence (persisté, s'applique à tout l'écran via
  `ExtendedColors` + `CompositionLocalProvider` — pas de couleurs codées en dur
  qui casseraient le mode clair).
- **Séparation risque / sûr** : l'écran Historique a maintenant 3 onglets
  (Tous / À risque / Sûrs), et le dashboard affiche deux compteurs distincts.
- **Moteur de détection enrichi** : nouvelles catégories — demande de code OTP,
  demande de coordonnées bancaires, menace/extorsion, offre trop belle pour être
  vraie, majuscules excessives — plus un signal **"expéditeur inconnu + usurpation"**
  qui croise le numéro affiché (non enregistré comme contact) avec le contenu du
  message. Une **sensibilité réglable** (Basse/Normale/Élevée) permet d'arbitrer
  entre faux positifs et arnaques manquées.
- **Écran "S'informer"** (4ᵉ onglet) : 6 fiches dépliables sur la reconnaissance
  du phishing, la sécurité Mobile Money, WhatsApp, l'ingénierie sociale, les
  bonnes pratiques générales, et la marche à suivre en cas de victime — contenu
  statique, disponible hors ligne.
- **Onboarding** avant toute demande de permission système, pour expliquer
  precisément ce que l'app va lire et pourquoi (meilleur taux d'acceptation).
- **9 tests unitaires** sur le moteur local (`RuleBasedDetectorTest`), incluant
  ton exemple exact et les nouveaux signaux.

## Comment ça capte WhatsApp sans API officielle

WhatsApp est chiffré de bout en bout : il n'existe aucune API pour lire les messages
depuis une autre app. La seule voie légitime et documentée par Google est le
`NotificationListenerService` — l'utilisateur autorise explicitement FishGuard,
dans les réglages Android, à lire le **contenu affiché dans les notifications**
(exactement ce que font Truecaller ou les bloqueurs de spam). C'est ce que fait
`notification/NotificationCaptureService.kt`. Les SMS sont en plus captés
directement via l'API `Telephony` officielle (`notification/SmsReceiver.kt`),
indépendamment de l'affichage d'une notification.

## Détection d'arnaques par appel téléphonique

Comme pour WhatsApp, une limite technique et légale s'impose : **aucune app ne
peut écouter le contenu d'un appel téléphonique classique**, et l'enregistrer
sans consentement est illégal dans beaucoup de pays. Depuis Android 10, Google
a explicitement fermé l'accès aux flux audio d'appel (`VOICE_CALL`,
`VOICE_UPLINK`/`VOICE_DOWNLINK`) à toute app qui n'est pas privilégiée par le
système, précisément pour empêcher ce genre d'usage — ce n'est pas une
politique du Play Store qu'on pourrait contourner en distribuant l'app
autrement, c'est verrouillé au niveau du système audio lui-même.

L'implémentation ici tient donc sur deux volets, tous les deux légitimes et
documentés :

### 1. Avant de décrocher — vérification du numéro (`calls/ScamCallScreeningService.kt`)

Utilise le rôle système officiel `ROLE_CALL_SCREENING` (le même qu'utilisent
Truecaller ou Google Téléphone) pour vérifier le **numéro appelant** — jamais
le contenu — contre une liste locale de numéros déjà signalés
(`ScamNumberEntity`/`ScamNumberDao`), avant même que le téléphone sonne.
Aucun blocage automatique (trop de risque de faux positif) : juste une
notification d'alerte. L'utilisateur doit accorder ce rôle une fois, depuis
Réglages > Protection des appels > "Activer la vérification des numéros" —
Android ne l'accorde jamais tout seul.

### 2. Pendant l'appel — protection en direct (haut-parleur + micro + Vosk)

Dès qu'un appel est décroché, une notification "Appel en cours" propose
d'activer la protection (`calls/CallStateReceiver.kt`). Si l'utilisateur
accepte, un **écran de consentement explicite** s'affiche d'abord
(`CallConsentScreen`) — jamais d'activation automatique ou silencieuse — qui
rappelle de mettre l'appel en haut-parleur et d'en informer l'interlocuteur.

Une fois confirmé, `CallProtectionService` (service de premier plan, type
`microphone`) capte le son ambiant via le micro standard — **FishGuard
n'accède jamais au flux télécom de l'appel**, seulement à ce que le
haut-parleur diffuse dans la pièce, exactement comme un dictaphone posé à
côté du téléphone. Ce son est transcrit **entièrement hors ligne** par
[Vosk](https://alphacephei.com/vosk/) (modèle français ~45 Mo), et chaque
fragment transcrit est envoyé au même `RuleBasedDetector` qui analyse déjà
les SMS (`calls/CallSessionAnalyzer.kt`) : le score s'accumule au fil de la
conversation et reste affiché en direct (`CallProtectionLiveScreen`), avec le
détail des signaux détectés (demande de code, urgence, usurpation...). Un
résumé complet est enregistré dans l'historique à la fin de l'appel.

**Rien n'est envoyé à un serveur** — ni l'audio, ni le texte transcrit —
même si le mode backend est activé dans les réglages : cette fonctionnalité
reste 100% locale par conception.

### Le modèle vocal et le fonctionnement hors ligne

Le modèle français Vosk (~45 Mo) est **téléchargé et embarqué directement
dans l'APK au moment de la compilation** par le pipeline GitHub Actions (voir
`.github/workflows/build-apk.yml`) — donc l'app fonctionne hors ligne dès
l'installation, sans rien à télécharger côté utilisateur. Si tu compiles en
local depuis Android Studio sans avoir lancé ce script, l'app détecte
l'absence du modèle embarqué et propose un téléchargement unique (avec barre
de progression) au premier lancement de la protection d'appel ; une fois
téléchargé, tout redevient hors ligne durablement.

## Ouvrir le projet

1. Android Studio (Koala ou plus récent) → **Open** → sélectionner ce dossier.
2. Laisser Gradle synchroniser (le projet cible Kotlin 1.9.24 / AGP 8.5.2 / SDK 34,
   `minSdk` 26 — couvre largement le parc Android en usage).
3. Lancer sur un appareil ou émulateur physique de préférence (le
   `NotificationListenerService` se teste mal sur certains émulateurs sans Play Store).

## Premier lancement

1. Un écran d'accueil explique ce que l'app va lire et pourquoi.
2. L'app demande ensuite la permission SMS et la permission de notification (Android 13+).
3. Sur le dashboard, un bandeau invite à activer l'**accès aux notifications**
   (obligatoire côté OS, aucune app ne peut se l'auto-accorder) → bouton "Activer" →
   Android ouvre ses réglages → cocher FishGuard.
4. C'est tout : les SMS et notifications WhatsApp reçus sont analysés en local,
   silencieusement. Une alerte système apparaît uniquement si le score dépasse
   le seuil "risque élevé" (55/100, ajustable via la sensibilité dans Réglages).

## Brancher ton backend Flask existant

Dans **Réglages > Moteur de détection** :
- Renseigne l'URL de ton serveur Flask (ex: `http://192.168.1.10:5000` en local,
  ou l'URL de prod).
- Active "Utiliser le backend quand disponible".

Le seul fichier à adapter si ton API a un format différent est
`detection/RemoteApiClient.kt` — la classe `AnalyzeResponse` doit correspondre
au JSON que retourne `/api/analyze`. Par défaut le client s'attend à :

```json
{ "score": 78, "classification": "phishing", "explanations": ["..."] }
```

Le mode local reste **toujours actif en secours** : si le backend est injoignable
(pas de réseau, serveur éteint), l'analyse locale prend le relais automatiquement,
sans interruption pour l'utilisateur.

## Où ajouter tes propres motifs de détection

`detection/ScamPatterns.kt` regroupe tous les motifs par catégorie
(usurpation, avance de frais, urgence, liens suspects, fausse loterie, vol de
code OTP, coordonnées bancaires, extorsion, offres trop belles, style suspect).
Chaque motif est une regex + un poids (0-100) + une explication affichée à
l'utilisateur dans le détail de la menace. Pour ajouter un nouveau schéma
d'arnaque observé sur le terrain, il suffit d'ajouter une entrée à la bonne liste.
Les combinaisons de signaux (bonus de score) et les heuristiques non-regex
(majuscules, incohérence expéditeur) sont dans `detection/RuleBasedDetector.kt`.

Pour ajouter du contenu à l'écran "S'informer", ajoute une entrée à
`ui/learn/LearnContent.kt` — pas besoin de toucher à l'écran lui-même.

## Ce qui manque encore pour une version production

- Tests instrumentés (UI) en complément des tests unitaires du moteur.
- Chiffrement local de la base Room si le téléphone est partagé (SQLCipher).
- Le "Signaler une erreur" (faux positif/négatif) sur une détection, pour
  affiner les règles au fil du temps — pas encore implémenté.
- Publication : nécessite une politique de confidentialité claire sur l'usage
  des permissions SMS/notifications/téléphone/micro pour passer la revue
  Google Play (catégories sensibles — prévoir ce point avant soumission ;
  `RECORD_AUDIO` + `READ_PHONE_STATE` demanderont probablement une
  justification écrite détaillée à Google).
- Protection d'appel : la reconnaissance vocale hors ligne (Vosk, modèle
  "small") a une précision correcte mais pas parfaite, surtout avec du bruit
  ambiant ou un haut-parleur de mauvaise qualité — ne jamais présenter le
  score comme une certitude absolue. Le modèle testé n'est pas encore validé
  sur des accents/expressions spécifiquement togolais·es ; à affiner avec de
  vrais enregistrements de test si possible.
- Le logo source (`poisson.png`/`poisson3.png`) contient un petit texte
  placeholder ("Lorem ipsum") probablement oublié par erreur près du crochet —
  à vérifier/nettoyer sur le fichier maître avant impression ou usage
  grand format (invisible sur l'icône de l'app, rognée avant ce point).

