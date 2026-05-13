# CLAUDE.md — WiredSwift

Notes pour Claude (et autres assistants IA) qui travaillent sur ce dépôt.

## Ce que ce repo contient

- **`WiredSwift`** : bibliothèque Swift — parser du protocole binaire Wired (P7),
  crypto (ECDSA/ECDH/ciphers), couche connexion/socket.
- **`wired3`** : daemon serveur — auth, chat, fichiers, boards, transferts.
- **`WiredServerApp`** : wrapper macOS GUI autour de `wired3`.

Arbre principal : `Sources/WiredSwift/{P7,Crypto,Network,Core}`.
Spec protocole : `Sources/WiredSwift/Resources/wired.xml`.

## Documentation déjà existante — lis-la avant d'agir

| Fichier | Quand le consulter |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, style, conventions de commit, workflow PR |
| [COMPATIBILITY.md](COMPATIBILITY.md) | **Toute modification de `wired.xml` doit suivre ces règles** |
| [SECURITY.md](SECURITY.md) | Politique de signalement de vulnérabilité |
| [README.md](README.md) | Vue d'ensemble, build, run |
| [CHANGELOG.md](CHANGELOG.md) | Historique des changements |

## Règles non négociables

1. **Compat protocole** : un changement de `wired.xml` requiert l'attribut
   `version="X.Y"` sur chaque entrée modifiée/ajoutée, le bump de la version
   racine du protocole, et un test dans `Tests/WiredSwiftTests/CompatibilityTests.swift`.
   Cf. [COMPATIBILITY.md](COMPATIBILITY.md).
2. **Sécurité d'abord** : ce code parse du réseau non fiable. Valide les
   longueurs, évite les force-unwraps sur des entrées du pair, ne fais jamais
   confiance à un payload.
3. **SwiftLint** : `swiftlint lint` doit passer. Pas de nouveau
   `// swiftlint:disable` sans `// TODO:` qui explique pourquoi.
4. **Conventional Commits** : `feat(scope): …`, `fix(scope): …`, etc. Scopes
   courants : `p7`, `auth`, `chat`, `files`, `lint`, `ci`.
5. **Jamais de commit direct sur `main`/`master`** — toujours via PR.

## Commandes utiles

```bash
swift build --product wired3
swift test
swiftlint lint
swiftlint --fix              # corrections stylistiques auto
```

Pre-commit hook (SwiftLint) : `bash Scripts/install-hooks.sh`.

## Review automatique

Les PR sont relues automatiquement par Claude (Sonnet 4.6) via
[.github/workflows/claude-review.yml](.github/workflows/claude-review.yml).
La review est indicative — elle ne bloque pas le merge. Le focus est :
sécurité, compatibilité protocole, qualité.
