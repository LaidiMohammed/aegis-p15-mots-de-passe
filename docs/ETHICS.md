# ETHICS — P15 — Analyse des mots de passe dans les systèmes d'authentification (AEGIS)

Engagements éthiques du projet — stand-alone, labo local, GPU refused, anti-cloud.

- **Cible** : [AEGIS Analyse des mots de passe dans les systèmes d'authentification](https://github.com/LaidiMohammed/aegis-p15-mots-de-passe)
- **Périmètre** : [AEGIS Analyse des mots de passe dans les systèmes d'authentification](https://aegis-p15-mots-de-passe.vercel.app) — smoke + fonctions CLI.
- **GPU refused** : implementation uniquement CPU/pure Python.
- **Données locales** : sources acceptées : labo local (localhost, Juice Shop, DVWA, etc.).
- **Smoke au prof** : cmds à exécuter — voir README/scripts/run_smoke.sh.
- **Smoke clé de validation** : voir `smoke()` dans `src/mots-de-passe_main.py` — doit retourner `{"ok": true, ...}`.
- **Site statique Vercel** : disponible pour la démo statique (smoke uniquement).

See SPEC.md (avec use cases + tableaux attendus).
