import argparse
import base64
import os
from base64 import b32decode
from time import time

from cbor2 import dumps as cbor_encode
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.pcsc import CtapPcscDevice

# === Fonctions utilitaires ===

def get_ctap2_device():
    dev = None
    try:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            dev = next(CtapPcscDevice.list_devices(), None)
    except Exception as e:
        raise RuntimeError("Erreur lors de la détection des périphériques FIDO2 : " + str(e))

    if not dev:
        raise RuntimeError("Aucun token FIDO2 détecté.")
    if not (dev.capabilities & CAPABILITY.CBOR):
        raise RuntimeError("Le token ne supporte pas CTAP2/CBOR.")
    return Ctap2(dev)

def generate_base32_seed(length=20):
    secret = os.urandom(length)
    return base64.b32encode(secret).decode('utf-8').replace('=', '')

# === Codes d'erreurs OTP personnalisés ===
OTP_ERROR_CODES = {
    0x00: ("OTP_OK", "OTP Command executed successfully"),
    0xF1: ("OTP_ERR_INVALID_CBOR", "La commande contient un encodage CBOR invalide"),
    0xF2: ("OTP_ERR_INVALID_COMMAND", "Commande OTP non reconnue"),
    0xF3: ("OTP_ERR_INVALID_PARAMETER", "Paramètre invalide dans la commande"),
    0xF4: ("OTP_ERR_GENERATOR_EXISTS", "Un générateur avec ce nom existe déjà"),
    0xF5: ("OTP_ERR_GENERATOR_NOT_FOUND", "Générateur introuvable"),
    0xF6: ("OTP_ERR_MEMORY_FULL", "Mémoire pleine, impossible de créer un autre générateur")
}

def handle_ctap_error(e):
    print(f"❌ Erreur CTAP : {str(e)}")
    if hasattr(e, 'code'):
        code = e.code
        label, desc = OTP_ERROR_CODES.get(code, (f"Code inconnu 0x{code:02X}", "Erreur non documentée"))
        print(f"🔍 {label} : {desc}")


# === Commandes OTP ===

def create_otp(ctap2, label, secret_b32=None, random=False, algo=4, digits=6, period=30):
    try:
        if random:
            secret_b32 = generate_base32_seed()
            print(f"🔐 Secret généré automatiquement (Base32) : {secret_b32}")
        if not secret_b32:
            raise ValueError("Aucun secret fourni. Utilisez --random-secret ou spécifiez une seed Base32.")

        secret_bytes = b32decode(secret_b32, casefold=True)
        payload = {
            1: label,
            2: 2,  # TOTP
            3: {
                1: 4,  # kty: symmetric
                3: algo,  # alg
               -1: secret_bytes
            },
            4: digits,
            6: period
        }
        ctap2.send_cbor(0xB1, payload)
        print(f"✅ OTP '{label}' créé avec succès.")
    except Exception as e:
        handle_ctap_error(e)

def generate_otp(ctap2, label, timestep=30):
    try:
        T = int(time()) // timestep
        T_bytes = T.to_bytes(8, 'big')
        payload = {1: label, -1: T_bytes}
        resp = ctap2.send_cbor(0xB2, payload)
        code = resp.get(1)
        if code:
            print(f"🔐 Code OTP pour '{label}' : {code}")
        else:
            print("⚠️ Aucune réponse ou code OTP vide.")
    except Exception as e:
        handle_ctap_error(e)

def list_otp(ctap2, index=0, count=None):
    try:
        payload = {}
        payload[1] = index  # 1 = index

        if count is not None:
            payload[2] = count  # 2 = count

        resp = ctap2.send_cbor(0xB4, payload)
        generators = resp.get(2, [])

        print(f"📋 Total : {resp.get(1, 0)} générateur(s) | Affichés : {len(generators)}")
        for g in generators:
            print(f" - {g[1]} | Type: {g[2]} | Algo: {g[3]} | Digits: {g[4]} | Period: {g.get(6, '-')}")
    except Exception as e:
        handle_ctap_error(e)


def delete_otp(ctap2, label):
    try:
        payload = {1: label}
        ctap2.send_cbor(0xB3, payload)
        print(f"🗑️ Générateur '{label}' supprimé avec succès.")
    except Exception as e:
        handle_ctap_error(e)

# === CLI ===

def main():
    parser = argparse.ArgumentParser(description="Gestion OTP sur token FIDO2 (Neowave)")
    subparsers = parser.add_subparsers(dest="command")

    # create
    p_create = subparsers.add_parser("create", help="Créer un OTP")
    p_create.add_argument("label", help="Nom du générateur")
    p_create.add_argument("--secret", help="Secret OTP en Base32")
    p_create.add_argument("--random-secret", action="store_true", help="Générer un secret automatiquement")
    p_create.add_argument("--algo", type=int, choices=[4, 5, 7], default=4, help="Algo: 4=SHA1, 5=SHA256, 7=SHA512")
    p_create.add_argument("--digits", type=int, choices=[6, 7, 8], default=6, help="Nombre de chiffres")
    p_create.add_argument("--period", type=int, choices=[30, 60], default=30, help="Période (en secondes)")

    # generate
    p_generate = subparsers.add_parser("generate", help="Générer un OTP")
    p_generate.add_argument("label", help="Nom du générateur")

    # list
    p_list = subparsers.add_parser("list", help="Lister les générateurs OTP")
    p_list.add_argument("--index", type=int, default=0, help="Index du premier OTP à retourner")
    p_list.add_argument("--count", type=int, help="Nombre maximum d'OTP à retourner")


    # delete
    p_delete = subparsers.add_parser("delete", help="Supprimer un générateur OTP")
    p_delete.add_argument("label", help="Nom du générateur à supprimer")

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
        create_otp(ctap2, args.label, args.secret, args.random_secret, args.algo, args.digits, args.period)
    elif args.command == "generate":
        generate_otp(ctap2, args.label)
    elif args.command == "list":
        list_otp(ctap2, args.index, args.count)
    elif args.command == "delete":
        delete_otp(ctap2, args.label)

if __name__ == "__main__":
    main()
