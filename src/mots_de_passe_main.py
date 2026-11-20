"""Module principal — P15 Analyse des mots de passe dans les systèmes d'authentification (AEGIS).

Fonctions :
  - analyze_password_strength(password) -> dict : analyse de la force d'un mot de passe
  - check_common_patterns(password) -> list[dict] : vérification des patterns courants
  - generate_report(passwords) -> dict : génération d'un rapport global
  - main(argv) -> int : CLI

Éthique : analyse locale uniquement, aucun mot de passe envoyé à des services distants.
Utilisation éducative : aide les utilisateurs à créer des mots de passe plus robustes.
"""
from __future__ import annotations

import argparse
import json
import re
import string
import time
from typing import Any, Dict, List, Optional

# Seuil d'entropie minimum recommandé
MIN_ENTROPY = 60  # bits environ pour un mot de passe considéré comme fort
# Longueur minimale recommandée
MIN_LENGTH = 12

# Patterns de mots de passe courants à éviter
COMMON_PATTERNS = [
    (r".{1,10}123456.{1,10}", "séquence numérique 123456"),
    (r".{1,10}password.{1,10}", "mot de passe en clair"),
    (r".{1,10}qwerty.{1,10}", "motif clavier qwerty"),
    (r".{1,10}admin.{1,10}", "identifiant admin"),
    (r".{1,10}welcome.{1,10}", "mot de bienvenue"),
    (r".{1,10}abc123.{1,10}", "motif alphanumérique abc123"),
    (r".{1,10}letmein.{1,10}", "expression d'accès"),
    (r".{1,10}monkey.{1,10}", "motif animal 'monkey'"),
    (r".{1,10}door.{1,10}", "motif 'door'"),
    (r".{1,10}master.{1,10}", "motif 'master'"),
]


def calculate_entropy(password: str) -> float:
    """Calcule l'entropie d'un mot de passe en bits (approximation par modèle de caractère uniforme)."""
    if not password:
        return 0.0
    # Nombre de caractères uniques possibles dans le mot de passe
    charset_size = len(set(password))
    length = len(password)
    # Entropie = longueur * log2(taille_du_jeu_de_caractères)
    # Modèle simplifié: on estime le jeu de caractères en fonction des types présents
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Estimation du taille du jeu de caractères
    if has_lower and has_upper and has_digit and has_special:
        charset_size_estimate = 26 + 26 + 10 + 32  # 94 caractères imprimables standards
    elif has_lower and has_upper and has_digit:
        charset_size_estimate = 26 + 26 + 10  # 62 caractères
    elif has_lower and has_digit:
        charset_size_estimate = 26 + 10  # 36 caractères
    elif has_lower:
        charset_size_estimate = 26  # seulement minuscules
    else:
        charset_size_estimate = 94  # jeu complet
    
    entropy = length * (charset_size_estimate.bit_length() if charset_size_estimate > 0 else 8)
    # Affinage: on utilise log2 plus précis
    import math
    entropy = length * math.log2(charset_size_estimate) if charset_size_estimate > 0 else 0
    return round(entropy, 2)


def check_common_patterns(password: str) -> List[Dict[str, Any]]:
    """Vérifie si le mot de passe contient des patterns courants faibles."""
    found: List[Dict[str, Any]] = []
    for pattern, description in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            found.append({
                "pattern": description,
                "matched": re.search(pattern, password, re.IGNORECASE).group(),
            })
    return found


def analyze_password_strength(password: str) -> Dict[str, Any]:
    """Effectue une analyse complète de la force d'un mot de passe."""
    length = len(password)
    entropy = calculate_entropy(password)
    common_patterns = check_common_patterns(password)
    
    # Déterminer le niveau de force
    if length >= MIN_LENGTH and entropy >= MIN_ENTROPY and not common_patterns:
        level = "très fort"
        recommendation = "Ce mot de passe est très sécurisé. Continuez à bonnes pratiques."
    elif length >= MIN_LENGTH and entropy >= MIN_ENTROPY - 15:
        level = "fort"
        recommendation = "Ce mot de passe est solide. Considérez tout de même une mise à jour périodique."
    elif length >= MIN_LENGTH - 3 and entropy >= 30:
        level = "moyen"
        recommendation = "Ce mot de passe est acceptable mais pourrait être renforcé. Ajoutez des caractères spéciaux."
    else:
        level = "faible"
        recommendation = "Ce mot de passe est trop faible. Il est strongly recommandé de le remplacer immédiatement."
    
    # Raisons détaillées
    reasons: List[str] = []
    if length < MIN_LENGTH:
        reasons.append(f"Trop court ({length} < {MIN_LENGTH} caractères recommandés)")
    if entropy < MIN_ENTROPY:
        reasons.append(f"Entropie faible ({entropy} bits < {MIN_ENTROPY} bits recommandés)")
    if common_patterns:
        reasons.append(f"Contient des patterns courants: {', '.join([p['pattern'] for p in common_patterns[:3]])}")
    if not common_patterns:
        reasons.append("Aucun pattern courant détecté (positif)")
    
    return {
        "password": "****" + password[-4:] if len(password) > 4 else "****",
        "length": length,
        "entropy": entropy,
        "level": level,
        "common_patterns": common_patterns,
        "reasons": reasons,
        "recommendation": recommendation,
    }


def generate_report(passwords_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Génère un rapport global pour plusieurs mots de passe."""
    if not passwords_data:
        return {"error": "Aucune donnée de mot de passe fournie"}
    
    # Statistiques globales
    total = len(passwords_data)
    levels: Dict[str, int] = {"très fort": 0, "fort": 0, "moyen": 0, "faible": 0}
    avg_entropy = sum(p.get("entropy", 0) for p in passwords_data) / total if total > 0 else 0
    total_common = sum(len(p.get("common_patterns", [])) for p in passwords_data)
    
    # Recommandations globales
    global_recs: List[str] = []
    if avg_entropy < 50:
        global_recs.append("Formation utilisateurs sur la création de mots de passe sécurisés recommandée")
    if any(p.get("level") == "faible" for p in passwords_data):
        global_recs.append("Remplacer tous les mots de passe 'faible' par des générateurs de mots de passe")
    if any(p.get("level") in ("moyen", "fort") for p in passwords_data):
        global_recs.append("Mettre en place une politique de rotation de mots de passe")
    
    return {
        "total_analyzed": total,
        "average_entropy": round(avg_entropy, 2),
        "level_distribution": levels,
        "total_common_patterns": total_common,
        "global_recommendations": global_recs,
        "individual_results": passwords_data,
    }


def main(argv: list[str] | None = None) -> int:
    import warnings
    warnings.filterwarnings("ignore")

    ap = argparse.ArgumentParser(prog="mots_de_passe",
                                 description="AEGIS - P15 - Analyse des mots de passe dans les systèmes d'authentification")
    ap.add_argument("--password", default=None, help="Mot de passe à analyser")
    ap.add_argument("--passwords-json", default=None, help="JSON de plusieurs mots de passe à analyser")
    ap.add_argument("--save-json", default=None, help="Écrire le résultat JSON")
    ap.add_argument("--pdf", default="outputs/rapport-p15.pdf", help="Chemin du PDF")
    ap.add_argument("--json", action="store_true", help="Sortir en JSON")
    args = ap.parse_args(argv)

    try:
        # Analyser un mot de passe unique
        if args.password:
            out = analyze_password_strength(args.password)
            out["project"] = "P15"
        # Analyser plusieurs mots de passe
        elif args.passwords_json:
            passwords = json.loads(args.passwords_json)
            out = generate_report([analyze_password_strength(p) for p in passwords])
            out["project"] = "P15"
        # Mode interactif sans arguments
        else:
            out = {"project": "P15", "note": "Utilisez --password <motdepasse> ou --passwords-json <json> pour analyser"}
        
    except Exception as exc:  # noqa: BLE001
        print(f"[ERREUR] {exc}")
        return 1

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        if args.password:
            pwd_label = f"Mot de passe analysé (longueur: {out.get('length', '?')}, entropie: {out.get('entropy', '?')} bits)"
            print(f"[SUMMARY] P15 - Analyse de mot de passe")
            print(f"  {pwd_label}")
            print(f"  Niveau: {out.get('level', 'N/A')}")
            if out.get("common_patterns"):
                print(f"  Patterns courants détectés: {len(out['common_patterns'])}")
            for reason in out.get("reasons", [])[:3]:
                print(f"  - {reason}")
            print(f"  Recommandation: {out.get('recommendation', 'N/A')}")
        elif args.passwords_json:
            out_label = f"Rapport analysant {out.get('total_analyzed', '?')} mots de passe"
            print(f"[SUMMARY] P15 - Rapport d'analyse de mots de passe")
            print(f"  {out_label}")
            print(f"  Entropie moyenne: {out.get('average_entropy', '?')} bits")
            td = out.get("level_distribution", {})
            print(f"  Répartition: très fort={td.get('très fort', 0)}, fort={td.get('fort', 0)}, "
                  f"moyen={td.get('moyen', 0)}, faible={td.get('faible', 0)}")
            if out.get("global_recommendations"):
                print(f"  Recommandation globale: {out['global_recommendations'][0]}")
        else:
            print(f"[SUMMARY] P15 - Analyse de mot de passe")
            print(f"  Aucun mot de passe spécifié")

    if args.save_json:
        p = Path(args.save_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] écriture : {p}")

    if args.save_json and args.pdf:
        from src.generate_report import main as gen_main
        rc = gen_main(["--json", args.save_json, "--pdf", args.pdf])
        if rc != 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())