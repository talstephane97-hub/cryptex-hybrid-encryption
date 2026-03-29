# CRYPTEX — Application de Chiffrement Hybride
### RSA-4096 · AES-256-GCM · Argon2id · SHA-256 · Signature RSA-PSS

---

## Installation

1. Ouvre un terminal dans ce dossier
2. Installe les dépendances :
   ```
   pip install -r requirements.txt
   ```
3. Lance l'application :
   ```
   python api.py
   ```
4. Le navigateur s'ouvre automatiquement sur http://127.0.0.1:8000/app

---

## Structure du projet

```
secure_crypto_app/
├── frontend/
│   ├── index.html       ← Interface utilisateur
│   ├── style.css        ← Thème dark mode cyber
│   └── app.js           ← Logique frontend
├── crypto_core.py       ← Module cryptographique (AES, RSA, Argon2id)
├── api.py               ← Backend FastAPI (point d'entrée)
├── key_manager.py       ← Gestion des clés RSA
├── exceptions.py        ← Exceptions personnalisées
├── logger.py            ← Logger sécurisé
├── config.py            ← Configuration globale
├── requirements.txt     ← Dépendances Python
└── README.md            ← Ce fichier
```

Les dossiers suivants sont créés automatiquement au premier lancement :
- `keys/`    → Stockage des clés RSA (.pem)
- `outputs/` → Fichiers chiffrés sauvegardés
- `logs/`    → Logs applicatifs et historique

---

## Sécurité

- Toutes les opérations sont locales (127.0.0.1) — aucune donnée externe
- La clé privée est chiffrée sur le disque via Argon2id + AES-256-CBC
- Pipeline complet : SHA-256 → Signature RSA-PSS → AES-256-GCM → RSA-OAEP
