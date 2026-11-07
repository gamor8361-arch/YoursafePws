#!/usr/bin/env python3
"""pwnsafe : audite la solidité d'un mot de passe et vérifie s'il a fuité,
sans jamais l'envoyer en clair (k-anonymity avec Have I Been Pwned)."""
import argparse
import getpass
import hashlib
import math
import secrets
import string
import sys
import urllib.error
import urllib.request

COMMON = {
    "password", "motdepasse", "azerty", "qwerty", "admin", "welcome", "letmein",
    "bonjour", "soleil", "doudou", "football", "iloveyou", "monkey", "dragon",
    "123456", "123456789", "000000", "111111", "abc123", "master", "login",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "azertyuiop", "qsdfghjklm", "1234567890"]
LEET = str.maketrans("04135@$", "oaleass")


def charset_size(pw):
    pool = 0
    if any(ch in string.ascii_lowercase for ch in pw):
        pool += 26
    if any(ch in string.ascii_uppercase for ch in pw):
        pool += 26
    if any(ch in string.digits for ch in pw):
        pool += 10
    if any(not ch.isalnum() for ch in pw):
        pool += 33
    return pool or 1


def has_sequence(pw):
    low = pw.lower()
    for i in range(len(low) - 2):
        a, b, c = map(ord, low[i:i + 3])
        if b - a == c - b and abs(b - a) == 1:
            return True
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def analyze(pw):
    issues = []
    normalized = pw.lower().translate(LEET)
    if normalized in COMMON or pw.lower() in COMMON:
        return 0.0, ["Mot de passe parmi les plus courants au monde"]

    entropy = len(pw) * math.log2(charset_size(pw))
    if len(set(pw)) < len(pw) * 0.6:
        entropy *= 0.7
        issues.append("Beaucoup de caractères répétés")
    if has_sequence(pw):
        entropy *= 0.7
        issues.append("Suite prévisible (abc, 1234, azerty…)")
    if any(word in normalized for word in COMMON):
        entropy *= 0.6
        issues.append("Contient un mot courant (même avec @ ou 0 à la place des lettres)")
    if len(pw) < 12:
        issues.append("Trop court : vise 12 caractères ou plus")
    return entropy, issues


def label(entropy):
    for limit, name in [(28, "Très faible 🔴"), (36, "Faible 🟠"), (60, "Moyen 🟡"), (80, "Fort 🟢")]:
        if entropy < limit:
            return name
    return "Excellent 💎"


def crack_time(entropy, guesses_per_sec=1e10):
    seconds = (2 ** entropy) / 2 / guesses_per_sec
    for unit, size in [("années", 31_557_600), ("jours", 86_400), ("heures", 3600), ("minutes", 60)]:
        if seconds >= size:
            value = seconds / size
            return f"{value:.2e} {unit}" if value > 1e9 else f"{value:,.0f} {unit}"
    return "instantané" if seconds < 1 else f"{seconds:.0f} secondes"


def pwned_count(pw):
    """Retourne le nombre de fuites connues. Seuls 5 caractères du hash sont envoyés."""
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "pwnsafe-educational", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h == suffix:
            return int(count)
    return 0


def cmd_check(args):
    pw = getpass.getpass("Mot de passe à tester (invisible) : ")
    if not pw:
        sys.exit("Aucun mot de passe saisi.")
    entropy, issues = analyze(pw)
    print(f"\n  Niveau       : {label(entropy)}")
    print(f"  Entropie     : {entropy:.0f} bits")
    print(f"  Craquage     : ~{crack_time(entropy)} (attaque hors ligne rapide)")
    for issue in issues:
        print(f"  ⚠️  {issue}")

    if args.offline:
        print("\n  Vérification des fuites ignorée (--offline).")
        return
    try:
        count = pwned_count(pw)
    except (urllib.error.URLError, TimeoutError):
        print("\n  Impossible de contacter l'API (pas de connexion ?).")
        return
    if count:
        print(f"\n  🚨 Ce mot de passe a fuité {count:,} fois. Ne l'utilise plus !")
    else:
        print("\n  ✅ Absent des fuites connues.")


def cmd_generate(args):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*-_=+?"]
    alphabet = "".join(pools)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(args.length))
        if all(any(ch in pool for ch in pw) for pool in pools):
            break
    print(pw)
    print(f"Entropie : {analyze(pw)[0]:.0f} bits", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Audit de mots de passe, respectueux de la vie privée.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="analyser un mot de passe")
    p_check.add_argument("--offline", action="store_true", help="ne pas interroger l'API de fuites")
    p_check.set_defaults(func=cmd_check)

    p_gen = sub.add_parser("generate", help="générer un mot de passe aléatoire sûr")
    p_gen.add_argument("-l", "--length", type=int, default=20)
    p_gen.set_defaults(func=cmd_generate)

    args = parser.parse_args()
    if args.cmd == "generate" and args.length < 8:
        sys.exit("Longueur minimale : 8.")
    args.func(args)


if __name__ == "__main__":
    main()
