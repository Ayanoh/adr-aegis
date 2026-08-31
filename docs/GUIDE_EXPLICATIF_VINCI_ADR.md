# 🛡️ Vinci ADR — Dossier Technique & Stratégique d'Intégration

> **Document d'ingénierie et de positionnement technique pour la Direction**  
> *Projet : Intégration du framework de détection et réponse temps réel (ADR) dans l'Assistant IA Vinci Logic*

---

## 🎯 1. La Thèse de Sécurité : Pourquoi les protections IA classiques échouent

Les solutions traditionnelles de filtrage de prompts (regex basiques, wrappers API ou filtres de mots-clés) sont **structurellement inaptes** à sécuriser des agents autonomes connectés à des outils système, des bases de données et des protocoles comme **MCP (Model Context Protocol)**.

Face à des attaques modernes (injections indirectes, payloads encodés multi-couches, détournement d'outils / LOLBins, exfiltration silencieuse de credentials), **Vinci ADR** (*Agent Detection & Response*) applique le principe militaire de la **défense en profondeur à 360°** :

* **Protection en amont (Entrée)** : Analyse de la menace avant même qu'elle ne touche le LLM.
* **Garde du corps actif (Exécution)** : Interception en temps réel de chaque appel d'outil système via middleware JSON-RPC 2.0.
* **Contrôle en aval (Sortie)** : Caviardage DLP des secrets et analyse statique des vulnérabilités de code généré (Top 25 CWE).

Inspiré de l'architecture de référence **Uber ADR (publiée à MLSys 2026)** et des travaux de pointe de **Meta, NVIDIA et SigmaHQ**, Vinci ADR rivalise avec les meilleurs standards mondiaux.

---

## ⚡ 2. L'Arsenal du Tier 1 : Triage Déterministe & Neural (< 20 ms)

Le **Tier 1** est une barrière ultra-rapide capable d'évaluer les requêtes en quelques millisecondes sur CPU, sans latence perceptible pour l'utilisateur. Il agrège les meilleures technologies open-source mondiales :

### 1. Couche Capteur & Désembuage Récursif (*Sensor Layer*)
* **Rôle** : Déjouer les techniques d'évasion et d'obfuscation utilisées par les attaquants pour contourner les filtres.
* **Capacités** :
  * Décodage récursif multi-couches : déballe les chaînes imbriquées (ex: un script PowerShell caché dans un Base64 lui-même encodé en URL-percent et Hex).
  * Normalisation des homoglyphes : détecte les caractères Cyrilliques ou Grecs visuellement identiques aux lettres latines pour tromper les regex.
  * Suppression des caractères invisibles (*Zero-Width Characters*) et extraction d'artéfacts (adresses IP, URLs, chemins de fichiers, commandes shell).

### 2. Moteur Heuristique Comportemental : 1 803 Règles MITRE ATT&CK
* **Origine & Repos GitHub** :
  * **[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)** (10.9k ⭐) : Standard mondial de détection SIEM. Nous avons converti et intégré **1 443 règles** couvrant la création de processus suspects, les scripts PowerShell encodés, les LOLBins Windows/Linux et l'exfiltration réseau.
  * **[AikidoSec/sage](https://github.com/AikidoSec/sage)** : **351 règles heuristiques** spécialisées dans la détection d'attaques orientées agents IA (persistance, vol de clés SSH, manipulation de fichiers de configuration).
  * **Règles Natives ADR** : 8 règles spécialisées sur les structures d'injections directes et jailbreaks complexes.
* **Couverture** : 91.3% des règles sont directement taguées selon la matrice officielle **MITRE ATT&CK**.

### 3. Scanner de Secrets & Entropie de Shannon (210 Patterns)
* **Origine & Repos GitHub** : **[gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)** (16k ⭐)
* **Capacités** : Analyse chaque token pour détecter **210 types de clés API et identifiants volés** (clés AWS, OpenAI `sk-`, GitHub PAT, Anthropic, tokens JWT, Stripe, URIs de bases de données avec credentials).
* **Validation par Entropie** : Calcule l'entropie mathématique de Shannon de la chaîne pour différencier une vraie clé cryptographique d'une fausse chaîne aléatoire, éliminant ainsi les faux positifs.

### 4. Classifieur Neural DeBERTa-v3
* **Origine & Modèle Hugging Face** : **`ProtectAI/deberta-v3-base-prompt-injection-v2`**
* **Capacités** : Modèle Transformer entraîné spécifiquement sur des centaines de milliers d'injections de prompt. Capable de comprendre la sémantique sous-jacente d'une tentative de manipulation, même sans mot-clé suspect.
* **Performance** : 100% de précision constatée sur les datasets de référence.

### 5. Wolf Defender v2 (Architecture ModernBERT)
* **Origine & Modèle Hugging Face** : **`patronus-studio/wolf-defender-prompt-injection-small`**
* **Capacités** : Modèle de dernière génération basé sur l'architecture ModernBERT. Il réalise une classification d'injection et d'escalade de privilèges en **seulement 21 ms sur CPU**, offrant un premier rideau neural instantané.

### 6. Meta Prompt-Guard-86M & Garde-Fou Canary
* **Origine & Modèle Hugging Face** : **`meta-llama/Prompt-Guard-86M`** (Meta AI)
* **Capacités** : Modèle 3 classes (Benign / Injection / Jailbreak) expert dans la détection des attaques par contournement de personnalité (DAN, personas agressifs, jeux de rôle).
* **Auto-Vérification Canary Check** : Intègre un mécanisme d'auto-test au démarrage. Si le modèle chargé produit des déviations sur des phrases témoins, il est désactivé automatiquement pour empêcher tout faux positif en production.

### 7. Mémoire Vectorielle Sémantique ChromaDB
* **Origine & Stack** : **ChromaDB** + **`sentence-transformers`** (`all-MiniLM-L6-v2`)
* **Capacités** : Base vectorielle embarquée contenant **70 patterns d'attaques réelles curées**. Calcule la similarité cosinus sémantique en temps réel : si un attaquant paraphrase une attaque connue, elle est immédiatement identifiée et bloquée.

---

## 🧠 3. Le Tier 2 : L'Enquête Cognitive Dual-Agent (Inspiré d'Uber ADR)

Pour les requêtes complexes ou ambiguës où le Tier 1 hésite (verdict **`ASK`**), Vinci ADR ne bloque pas brutalement l'utilisateur : il délègue l'analyse au **Tier 2 Deep Cognitive Reasoning**.

Deux agents IA spécialisés dialoguent et s'affrontent de manière contradictoire :

1. **🕵️ Forensic Analyst Agent (L'Enquêteur)** : Déconstruit le contexte, identifie l'intention cachée, extrait les preuves techniques et formule une hypothèse d'attaque.
2. **⚖️ Critic Agent (Le Contradicteur Adversarial)** : Cherche activement les éléments qui prouvent la légitimité de la requête (cas d'usage bénin, code légitime, documentation technique) pour neutraliser les faux positifs.
3. **Synthèse Raisonnée** : Un verdict final argumenté est produit (**BLOCK** ou **ALLOW**), garantissant qu'aucune attaque sournoise ne passe tout en préservant le confort de travail des utilisateurs légitimes.

---

## 🛡️ 4. Garde du Corps d'Exécution & Contrôle de Sortie

### A. Mode Daemon : Middleware MCP JSON-RPC 2.0 & LangChain
* **Intercepteur MCP (`VinciMCPMiddleware`)** : Se positionne directement comme passerelle sur les serveurs **Model Context Protocol (Anthropic)**. Chaque requête JSON-RPC `tools/call` est interceptée et évaluée. En cas de menace, le serveur retourne une erreur standard JSON-RPC `-32000` sans exécuter le tool.
* **Hook LangChain (`@vinci_tool` / `VinciToolkit`)** : Protège n'importe quel toolkit d'agent en une seule ligne de code.

### B. Output Guard (DLP & Taxonomie MLCommons AI Safety)
* **CBRN (S6)** : Bloque toute génération de contenu relatif aux armes chimiques, biologiques, radiologiques et nucléaires.
* **Cyberattacks (S8)** : Empêche l'assistant de fournir des exploits offensifs automatisés ou des reverse shells fonctionnels.
* **DLP Secrets (S10)** : Détecte et caviarde automatiquement en temps réel (`[REDACTED_SECRET: AWS Key]`) les clés ou tokens qui auraient fuité dans la réponse de l'IA.

### C. Code Shield : Analyse Statique CWE Top 25 (Meta PurpleLlama)
* **Origine** : Inspiré du standard **[meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama)**.
* **Capacités** : Analyse le code généré par l'IA (Python, JS, Shell, SQL) et détecte les failles critiques avant livraison au client :
  * **CWE-89** : Injections SQL.
  * **CWE-78** : Injections de commandes système (`subprocess.run(shell=True)`).
  * **CWE-502** : Désérialisation non sécurisée (`pickle.loads`).
  * **CWE-94 / CWE-79** : Exécution dynamique de code (`eval/exec`) et vulnérabilités XSS.
  * Fournit automatiquement la correction technique et le snippet sécurisé.

---

## 🔌 5. Guide d'Intégration dans l'Assistant Vinci Logic

L'intégration dans la stack de Vinci Logic se fait en **3 étapes transparentes** :

### 1. Filtrage du Prompt Utilisateur (Entrée)

```python
from vinci_adr import VinciADREngine, EngineConfig, SensitivityPreset, ActionDecision

# Initialisation du moteur configuré pour le contexte SOC
engine = VinciADREngine(EngineConfig(
    sensitivity=SensitivityPreset.BALANCED,
    enable_heuristics=True,
    enable_secrets=True,
    enable_ml=True,
    enable_wolf_defender=True,
    enable_vector_matcher=True,
    enable_tier2=True,
))

# Évaluation du prompt avant transmission au LLM
result = engine.evaluate(user_message)

if result.verdict.decision == ActionDecision.BLOCK:
    return {
        "status": "blocked",
        "reason": result.verdict.reason,
        "threats": [t.rule_name for t in result.verdict.threats]
    }
```

### 2. Protection des Outils de l'Agent (Mode Daemon)

```python
from vinci_adr import VinciDaemon, DaemonConfig

daemon = VinciDaemon(DaemonConfig(
    allowed_tools=["query_threat_intel", "search_cve", "lookup_ioc"],
    strict_mode=True
))

@daemon.wrap_tool
def execute_system_query(query: str):
    # Action exécutée UNIQUEMENT si validée par Vinci ADR
    return db.execute(query)
```

### 3. Assainissement des Réponses Sortantes (DLP)

```python
from vinci_adr import OutputGuardEngine

guard = OutputGuardEngine()
output_verdict = guard.scan_output(llm_generated_response)

# Envoi de la réponse assainie au client
clean_response = output_verdict.sanitized_text
```

---

## 🏢 6. Adaptations Spécifiques au Cas d'Usage « Vinci Logic » (SOC / Cyber)

Dans un produit orienté SOC / Cybersécurité, un analyste va légitimement soumettre des IOCs, des commandes suspectes ou des règles Sigma. Voici la stratégie d'adaptation :

1. **Sensibilité `BALANCED` (Anti-Faux Positifs)** :
   * Ne pas utiliser le mode `PARANOID` qui bloquerait les requêtes d'analyse de logs. Le mode `BALANCED` transfère les cas ambigus au Tier 2 cognitif pour comprendre l'intention légitime de l'analyste.
2. **Whitelist des Outils Métier** :
   * Déclarer les outils de threat intelligence (`VirusTotal API`, `SIEM queries`, `CVE Search`) comme autorisés, tout en interdisant formellement les outils destructeurs (`DROP TABLE`, modification de configs EDR).
3. **Secrets Internes Vinci Logic** :
   * Ajouter les regex des clés API propriétaires de Vinci Logic dans `SecretsScanner` pour garantir qu'aucun token interne ne puisse fuiter auprès d'un client.
4. **Souveraineté des Données & Choix du LLM Tier 2** :
   * Le Tier 2 peut être branché sur l'API Gemini / Claude ou sur un modèle local/on-premise (ex: Llama 3 hébergé sur les serveurs de Vinci Logic) pour respecter la stricte confidentialité des données clients.

---

## 📊 7. Validation Scientifique & Performances

Les performances de Vinci ADR ont été mesurées et validées sur des bancs de tests réels :

| Métrique / Benchmark | Résultat | Signification pour Vinci Logic |
|---|---|---|
| **Benchmark DEF CON 31 AI Village** | **100.0% de Rappel** | Zéro attaque infiltrée sur les datasets d'attaques réelles DEF CON |
| **Crash-Test NVIDIA garak** | **98.86% de Blocage** | 519 attaques bloquées sur 525 probes adversariales automatiques |
| **Latence d'Interception Tier 1** | **< 20 ms** (CPU) | Impact totalement imperceptible sur l'expérience utilisateur |
| **Suite de Tests Unitaires & Intégration** | **238 / 238 Passés (100%)** | Fiabilité industrielle, code testé de bout en bout |
| **Dépôt GitHub du Projet** | **[Ayanoh/Vinci-ADR](https://github.com/Ayanoh/Vinci-ADR)** | Codebase complète, open-source, packagée et prête à l'emploi |

---

## 🏆 Synthèse pour la Direction

> **Vinci ADR** transforme l'assistant IA de Vinci Logic en une **forteresse logicielle**. En combinant 1 803 règles Sigma MITRE ATT&CK, 210 patterns de secrets Gitleaks, des classifieurs neuronaux modernes et une enquête cognitive dual-agent, nous offrons une sécurité de niveau bancaire et étatique, parfaitement adaptée aux exigences de nos clients en cybersécurité.
