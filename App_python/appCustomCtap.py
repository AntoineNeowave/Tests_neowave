import argparse
import base64
import os
from base64 import b32decode
from urllib.parse import urlparse, parse_qs, unquote
from time import time
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.pcsc import CtapPcscDevice
# === Constantes ===

OTP_CREATE = 0xB1
OTP_GENERATE = 0xB2
OTP_DELETE = 0xB3
OTP_ENUMERATE = 0xB4

ALG_NAME_TO_CODE = {'SHA1': 4, 'SHA256': 5, 'SHA512': 7}
ALG_CODE_TO_NAME = {v: k for k, v in ALG_NAME_TO_CODE.items()}
TYPE_NAME = {1: "HOTP", 2: "TOTP"}

OTP_ERROR_CODES = {
    0x00: ("OTP_OK", "OTP Command executed successfully"),
    0xF1: ("OTP_ERR_INVALID_CBOR", "La commande contient un encodage CBOR invalide"),
    0xF2: ("OTP_ERR_INVALID_COMMAND", "Commande OTP non reconnue"),
    0xF3: ("OTP_ERR_INVALID_PARAMETER", "Paramètre invalide dans la commande"),
    0xF4: ("OTP_ERR_GENERATOR_EXISTS", "Un générateur avec ce nom existe déjà"),
    0xF5: ("OTP_ERR_GENERATOR_NOT_FOUND", "Générateur introuvable"),
    0xF6: ("OTP_ERR_MEMORY_FULL", "Mémoire pleine, impossible de créer un autre générateur")
}

# === Fonctions utilitaires ===

def get_ctap2_device():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        dev = next(CtapPcscDevice.list_devices(), None)
    if not dev:
        raise RuntimeError("Aucun token FIDO2 détecté.")
    if not (dev.capabilities & CAPABILITY.CBOR):
        raise RuntimeError("Le token ne supporte pas CTAP2/CBOR.")
    return Ctap2(dev)

def generate_base32_seed(algo: str) -> str:
    length = {
        'SHA1': 20,
        'SHA256': 32,
        'SHA512': 64
    }.get(algo.upper(), 20)
    secret = os.urandom(length)
    return base64.b32encode(secret).decode('utf-8')

def parse_otpauth_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme != 'otpauth':
        raise ValueError("URI invalide : doit commencer par otpauth://")
    otp_type = parsed.netloc.upper()
    if otp_type not in ['TOTP', 'HOTP']:
        raise ValueError("Type OTP non supporté : " + otp_type)
    label = unquote(parsed.path.lstrip('/'))
    params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
    if 'secret' not in params:
        raise ValueError("Le champ 'secret' est obligatoire dans l'URI otpauth")
    
    alg = params.get('algorithm', 'sha1').upper()
    if alg not in ['SHA1', 'SHA256', 'SHA512']:
        print(f"⚠️  Algorithme '{alg}' non supporté, utilisation de SHA1 par défaut.")
        alg = 'SHA1'

    digits = int(params.get('digits', 6))
    if digits not in [6, 7, 8]:
        print(f"⚠️  Valeur de digits '{digits}' non supportée, utilisation de 6 par défaut.")
        digits = 6

    if otp_type == 'TOTP':
        period = int(params.get('period', 30))
        if period not in [30, 60]:
            print(f"⚠️  Valeur de period '{period}' non supportée, utilisation de 30 par défaut.")
            period = 30
    else:
        period = None

    if otp_type == 'HOTP':
        counter = int(params.get('counter', 0))
    else:
        counter = None

    return {
        "label": label,
        "type": otp_type,
        "secret_b32": params['secret'],
        "alg": alg,
        "digits": digits,
        "period": period,
        "counter": counter
    }

def handle_ctap_error(e):
    print(f"❌ Erreur CTAP : {str(e)}")
    if hasattr(e, 'code'):
        code = e.code
        label, desc = OTP_ERROR_CODES.get(code, (f"Code inconnu 0x{code:02X}", "Erreur non documentée"))
        print(f"🔍 {label} : {desc}")

def create_otp(ctap2, label, otp_type, secret_b32=None, random=False, algo='SHA1', digits=6, period=30, counter=None):
    try:
        if random:
            secret_b32 = generate_base32_seed(algo)
            print(f"🔐 Secret généré automatiquement (Base32) : {secret_b32}")
        if not secret_b32:
            raise ValueError("Aucun secret fourni. Utilisez --random-secret ou spécifiez une seed Base32.")
        algo_code = ALG_NAME_TO_CODE[algo.upper()]
        if otp_type == 'hotp'.upper():
            otp_type_code = 1
        elif otp_type == 'totp'.upper():
            otp_type_code = 2
        else:
            raise ValueError("Type OTP non supporté : doit être 'HOTP' ou 'TOTP'")
        secret_bytes = b32decode(secret_b32, casefold=True)
        payload = {
            1: label,
            2: otp_type_code,
            3: {
                1: 4,
                3: algo_code,
                -1: secret_bytes
            },
            4: digits,
        }
        if otp_type_code == 1 and counter is not None:
            payload[5] = int(counter).to_bytes(8, 'big')
        elif otp_type_code == 2 and period is not None:
            payload[6] = period
        ctap2.send_cbor(OTP_CREATE, payload)
        print(f"✅ OTP '{label}' créé avec succès.")
    except Exception as e:
        handle_ctap_error(e)

def generate_otp(ctap2, label):
    try:

        # D'abord, déterminer le type du générateur
        resp = ctap2.send_cbor(OTP_ENUMERATE, {})
        generators = resp.get(2, [])
        gen = next((g for g in generators if g.get(1) == label), None)
        if not gen:
            print("❌ Générateur non trouvé.")
            return

        otp_type = gen.get(2)  # 1 = HOTP, 2 = TOTP
        payload = {1: label}

        if otp_type == 2:  # TOTP
            T = int(time()) // gen.get(6, 30)  # période par défaut = 30
            T_bytes = T.to_bytes(8, 'big')
            payload[2] = T_bytes  # champ `time` requis
        print(f"🔄 Génération du code OTP pour '{label}'...")

        resp = ctap2.send_cbor(OTP_GENERATE, payload)
        code = resp.get(1)
        if code:
            print(f"🔐 Code OTP pour '{label}' : {code}")
        else:
            print("⚠️ Aucune réponse ou code OTP vide.")
    except Exception as e:
        handle_ctap_error(e)

def enumerate_otp(ctap2, index=None, count=None):
    try:
        if index is None and count is not None:
            payload = {2: count}
        elif index is not None and count is None:
            payload = {1: index}
        elif index is not None and count is not None:
            payload = {1: index, 2: count}
        else:
            payload = {}

        resp = ctap2.send_cbor(OTP_ENUMERATE, payload)

        total = resp.get(1, 0)
        generators = resp.get(2, [])
        print(f"📋 Total : {total} générateur(s) | Affichés : {len(generators)}")

        display_index = index+1 if index is not None else 1
        for i, g in enumerate(generators):
            label = g.get(1)
            type = TYPE_NAME.get(g.get(2), str(g.get(2)))
            alg = ALG_CODE_TO_NAME.get(g.get(3), str(g.get(3)))
            digits = g.get(4)
            counter = g.get(5)
            counter_str = int.from_bytes(counter, 'big') if counter else "-"
            period = g.get(6, "-")

            print(f"#{i + display_index} → {label} | Type: {type} | Algo: {alg} | Code length: {digits} | Timestep: {period} | Counter: {counter_str}")

    except Exception as e:
        handle_ctap_error(e)


def delete_otp(ctap2, label):
    try:
        payload = {1: label}
        ctap2.send_cbor(OTP_DELETE, payload)
        print(f"🗑️ Générateur '{label}' supprimé avec succès.")
    except Exception as e:
        handle_ctap_error(e)

# === CLI ===

def main():
    parser = argparse.ArgumentParser(description="Gestion OTP sur token FIDO2 (Neowave)", epilog="Exemple : python ./app create Alice HOTP --algo SHA256")
    subparsers = parser.add_subparsers(dest="command")

    p_create = subparsers.add_parser("create", help="Créer un OTP")
    p_create.add_argument("user", help="Identifiant utilisateur")
    p_create.add_argument("type", type=str.upper, choices=["HOTP", "TOTP"], help="Type de l'OTP (HOTP ou TOTP)")
    p_create.add_argument("--secret", help="Secret OTP en Base32")
    p_create.add_argument("--random-secret", action="store_true", help="Générer un secret automatiquement")
    p_create.add_argument("--algo", type=str.upper, choices=["SHA1", "SHA256", "SHA512"], default="SHA1", help="Algorithme HMAC")
    p_create.add_argument("--code-length", type=int, choices=[6, 7, 8], default=6, help="Longueur du code OTP")
    p_create.add_argument("--timestep", type=int, choices=[30, 60], default=30, help="Durée de validité du code (pour TOTP)")
    p_create.add_argument("--counter", type=int, help="Valeur initiale du compteur (pour HOTP)")

    p_uri = subparsers.add_parser("from-uri", help="Créer un OTP depuis un URI otpauth://")
    p_uri.add_argument("uri", help="URI otpauth:// complet")

    p_generate = subparsers.add_parser("generate", help="Générer un OTP")
    p_generate.add_argument("user", help="Identifiant utilisateur")

    p_enumerate = subparsers.add_parser("list", help="Lister les générateurs OTP")
    p_enumerate.add_argument("--index", type=int, help="Index de départ")
    p_enumerate.add_argument("--count", type=int, help="Nombre d'éléments à retourner")

    p_delete = subparsers.add_parser("delete", help="Supprimer un générateur OTP")
    p_delete.add_argument("user", help="Nom du générateur à supprimer")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    try:
        ctap2 = get_ctap2_device()
    except Exception as e:
        print("🚫 Erreur de connexion au token :", e)
        return

    if args.command == "create":
        create_otp(ctap2, args.user, args.type, args.secret, args.random_secret,
                   args.algo, args.code_length, args.timestep, args.counter)
    elif args.command == "from-uri":
        try:
            parsed = parse_otpauth_uri(args.uri)
            create_otp(ctap2, parsed["label"], parsed["type"], parsed["secret_b32"], False,
                parsed["alg"],parsed["digits"], parsed["period"], parsed["counter"])
        except Exception as e:
            print("❌ Erreur parsing URI :", e)
    elif args.command == "generate":
        generate_otp(ctap2, args.user)
    elif args.command == "list":
        enumerate_otp(ctap2, args.index, args.count)
    elif args.command == "delete":
        delete_otp(ctap2, args.user)

if __name__ == "__main__":
    main()