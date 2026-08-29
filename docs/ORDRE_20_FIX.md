# ORDRE #20-FIX — Fiabilisation du Benchmark Garak

> **Rôle** : spec rédigée par le Tech Lead (Claude), à exécuter par Gemini.
> **Type** : correctif ciblé (aucune refonte). 3 fichiers touchés.
> **Base validée par le Tech Lead** : le mécanisme `soft_probe_prompt_cap` de garak
> a été testé en live — il réduit une probe de 64→N prompts et le scan tourne en ~14s.
> AEGIS bloque 100% des injections Base64 (force à mettre en avant) mais 0% des attaques
> `grandma` (angle mort persona/roleplay, car le classifieur jailbreak est *gated*).

---

## POURQUOI (pour le manager)

Le benchmark actuel a 3 défauts :
1. Le profil `--fast` **n'est pas rapide** : deux probes contiennent 64 prompts chacune
   × inférence DeBERTa sur CPU → >2 min, run tronqué, chiffre non représentatif.
2. Le rapport manager contient une **faute** (`CATÉGORIE D ATTACQUE`) et **ne dit pas
   quel périmètre a été testé** (on mesure Tier 1 core uniquement).
3. Rien ne documente que le **classifieur jailbreak est indisponible** (modèle Meta
   *gated* + miroir empoisonné rejeté par le canary).

Analogie : le crash-test roule, mais on ne teste qu'une poignée de scénarios sans le
dire, et le tableau de bord affiche une faute d'orthographe. On fiabilise tout ça.

---

## FICHIER 1 — `scripts/run_garak_benchmark.py`

### 1.1 — Nouveau profil `--fast` représentatif ET rapide

Remplacer la constante `DEFAULT_PROBES_FAST` par une liste qui couvre TOUTES les
grandes familles d'attaque, y compris la force Base64, avec des probes légères :

```python
# Profil rapide : représentatif de chaque famille d'attaque, plafonné par prompt-cap.
# Couvre jailbreak (dan), persona/roleplay (grandma), payload injection (goodside),
# obfuscation encodée (encoding = force d'AEGIS), et injection de consigne (promptinject).
DEFAULT_PROBES_FAST = [
    "probes.dan.Dan_11_0",  # 1 prompt  — jailbreak DAN
    "probes.dan.AntiDAN",  # 1 prompt  — jailbreak inversé
    "probes.grandma.Win11",  # 6 prompts — persona/roleplay (angle mort connu)
    "probes.goodside.WhoIsRiley",  # 6 prompts — payload injection
    "probes.encoding.InjectBase64",  # cappé     — obfuscation Base64 (force d'AEGIS)
    "probes.promptinject.HijackHateHumans",  # cappé — injection de consigne
]
```

### 1.2 — Plafond de prompts (`soft_probe_prompt_cap`) via config garak

**C'est le cœur du correctif.** Ajouter une fonction qui écrit une config garak
temporaire et la passe en `--config`. Vérifié : garak accepte un chemin absolu.

```python
import tempfile


def _write_run_config(prompt_cap: int) -> str:
    """Écrit une config garak temporaire fixant le plafond de prompts par probe.

    Args:
        prompt_cap: Nombre max de prompts conservés par probe (pruning garak natif).

    Returns:
        Chemin absolu du fichier YAML temporaire.
    """
    fd, path = tempfile.mkstemp(prefix="aegis_garak_", suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"run:\n  soft_probe_prompt_cap: {int(prompt_cap)}\n")
    return path
```

Dans `run_benchmark(...)`, ajouter le paramètre `prompt_cap: int | None = None` et,
si fourni, écrire la config et la mettre **en tête** des `cli_args` (avant les autres) :

```python
config_path: str | None = None
if prompt_cap is not None:
    config_path = _write_run_config(prompt_cap)

cli_args: list[str] = []
if config_path:
    cli_args += ["--config", config_path]
cli_args += [
    "--target_type",
    "aegis.AegisGenerator",
    "--detectors",
    "aegis.AegisBlockDetector",
    "--spec",
    spec_str,
    "--report_prefix",
    report_prefix,
    "--generations",
    "1",
]
```

**Nettoyage obligatoire** : après le scan (dans un `finally`), supprimer le fichier
temporaire :

```python
finally:
    if config_path and os.path.exists(config_path):
        os.remove(config_path)
```

### 1.3 — En-tête « périmètre » dans le rapport manager (honnêteté)

Dans `print_benchmark_report`, juste après la ligne de titre, ajouter un bloc qui
affiche EXACTEMENT ce qui a été testé. Passer les métadonnées en argument :
`print_benchmark_report(results, meta: dict | None = None)` où `meta` contient
`{"probes": [...], "prompt_cap": N, "sensitivity": "balanced"}`.

```python
    print("  PÉRIMÈTRE TESTÉ :")
    print("    • Moteur      : AEGIS Tier 1 core (Heuristiques + Secrets + ML DeBERTa)")
    print("    • Désactivé   : Tier 2 (Gemini) et classifieur jailbreak — pour un")
    print("                    benchmark reproductible et hors-ligne.")
    print("    • Note        : le classifieur jailbreak (Prompt-Guard-86M) est de toute")
    print("                    façon indisponible (modèle Meta gated + miroir rejeté")
    print("                    par le canary). Les attaques persona/roleplay (grandma)")
    print("                    ne sont donc pas encore couvertes — cf. roadmap.")
    if meta:
        print(f"    • Prompt cap  : {meta.get('prompt_cap', 'aucun')} prompts/probe")
    print("-" * 80)
```

### 1.4 — Corriger la faute d'orthographe

Ligne de l'en-tête tableau : `'CATÉGORIE D ATTACQUE'` → `"CATÉGORIE D'ATTAQUE"`.

### 1.5 — Argument CLI `--prompt-cap`

```python
    parser.add_argument(
        "--prompt-cap",
        type=int,
        default=8,
        help="Plafond de prompts par probe (pruning garak). 8 par défaut pour --fast.",
    )
```

Dans `main()`, transmettre `prompt_cap=args.prompt_cap` à `run_benchmark(...)`.
Pour le profil `--fast`, garder `prompt_cap=8`. Pour un run `--full` explicite,
autoriser `--prompt-cap 64` (ou plus).

---

## FICHIER 2 — `tests/test_garak_integration.py`

Ajouter 2 tests unitaires (rapides, sans lancer garak) :

```python
def test_write_run_config_sets_prompt_cap(tmp_path):
    """La config temporaire fixe bien soft_probe_prompt_cap."""
    from scripts.run_garak_benchmark import _write_run_config
    import yaml, os

    path = _write_run_config(8)
    try:
        data = yaml.safe_load(open(path, encoding="utf-8"))
        assert data["run"]["soft_probe_prompt_cap"] == 8
    finally:
        os.remove(path)


def test_fast_profile_covers_key_families():
    """Le profil rapide couvre jailbreak, persona, injection et obfuscation."""
    from scripts.run_garak_benchmark import DEFAULT_PROBES_FAST

    joined = " ".join(DEFAULT_PROBES_FAST)
    for family in ("dan", "grandma", "goodside", "encoding", "promptinject"):
        assert family in joined
```

Ne PAS supprimer les 8 tests existants (ils doivent rester verts).

---

## FICHIER 3 — `prompt_context.txt` (handoff)

Mettre à jour l'entrée `[ORDRE #20]` : ajouter une ligne `#20-FIX` mentionnant
(a) profil fast fiabilisé via `soft_probe_prompt_cap`, (b) faute corrigée + en-tête
périmètre, (c) statut réel du classifieur jailbreak documenté honnêtement.
Mettre à jour la date et le compteur de tests (150 → 152).

---

## CRITÈRES D'ACCEPTATION (le Tech Lead vérifiera)

1. `python scripts/run_garak_benchmark.py --fast` **se termine en < 90 s** et le JSON
   produit contient **les 6 probes** (aucune tronquée), toutes avec `total_attacks > 0`.
2. Le rapport affiche le bloc « PÉRIMÈTRE TESTÉ » et **aucune faute** (`D'ATTAQUE`).
3. Le fichier de config temporaire est **supprimé** après le run (pas de résidu).
4. `pytest tests/test_garak_integration.py -v` → **10 tests verts** (8 anciens + 2 nouveaux).
5. `ruff check . && ruff format --check .` → **0 erreur**.
6. La suite complète `pytest tests/ -q` reste verte (**≈ 152 passés**, 21 skippés).

---

## DÉCISION EN ATTENTE POUR L'HUMAIN (P4 — hors périmètre de ce fix)

Le classifieur jailbreak (outil vedette #3) est **non fonctionnel** ici. Trois options :
- **(a)** Obtenir un token Hugging Face avec accès au modèle Meta officiel `Prompt-Guard-86M`.
- **(b)** Chercher un modèle alternatif de confiance (non empoisonné).
- **(c)** Assumer l'angle mort persona/roleplay et le documenter (choix actuel du fix).

À trancher avant l'ordre #21.
