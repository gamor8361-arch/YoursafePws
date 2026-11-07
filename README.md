# 🛡️ pwnsafe

> Teste la solidité de ton mot de passe et découvre s'il a déjà fuité, **sans jamais l'envoyer en clair**.

Outil de cybersécurité **défensif** et éducatif. Zéro dépendance : Python 3.7+ uniquement.

## ✨ Fonctionnalités

- 📊 **Estimation de l'entropie** et du temps de craquage
- 🔍 **Détection de mauvaises habitudes** : suites (`1234`, `azerty`), répétitions, mots courants déguisés (`P@ssw0rd`)
- 🌐 **Vérification des fuites** via l'API [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- 🎲 **Générateur** de mots de passe avec un aléa cryptographique (`secrets`)
- 🙈 Saisie **invisible** : le mot de passe n'apparaît ni à l'écran ni dans l'historique du shell

## 🔐 Respect de la vie privée (k-anonymity)

Ton mot de passe ne quitte jamais ta machine :

1. Il est haché en SHA-1 localement.
2. Seuls les **5 premiers caractères** du hash sont envoyés à l'API.
3. L'API renvoie tous les suffixes correspondant à ce préfixe.
4. La comparaison finale se fait **en local**.

Le service ne peut donc pas savoir quel mot de passe tu testes.

## 🚀 Utilisation

```bash
git clone https://github.com/TON-PSEUDO/pwnsafe.git
cd pwnsafe

python3 pwnsafe.py check              # analyser un mot de passe
python3 pwnsafe.py check --offline    # sans aucune connexion réseau
python3 pwnsafe.py generate -l 24     # générer un mot de passe de 24 caractères
```

## ⚖️ Éthique et limites

- Teste **uniquement tes propres mots de passe**. Cet outil n'est pas fait pour tester ceux des autres.
- L'estimation d'entropie est une **approximation pédagogique**, pas une garantie. Un gestionnaire de mots de passe (Bitwarden, KeePass…) et l'authentification à deux facteurs restent les meilleures protections.
- Le temps de craquage suppose une attaque hors ligne rapide (10 milliards d'essais par seconde).

## 🗺️ Idées d'améliorations

- [ ] Générateur de phrases de passe (diceware)
- [ ] Liste de mots courants plus complète (fr/en)
- [ ] Analyse d'un fichier d'export de gestionnaire de mots de passe (en local)
- [ ] Tests unitaires avec `pytest`

## 📄 Licence

MIT
