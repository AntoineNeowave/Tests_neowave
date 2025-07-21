from fido2.hid import CAPABILITY, CtapHidDevice
from fido2.pcsc import CtapPcscDevice
from fido2.ctap2 import Ctap2
from fido2.cbor import decode, encode
from cbor2 import dumps
import binascii
from time import time

dev = next(CtapPcscDevice.list_devices(), None)
dev = dev or next(CtapHidDevice.list_devices(), None)
if not dev:
    raise RuntimeError("Aucun token FIDO2 détecté")

# 2. Vérifier support CBOR
if not (dev.capabilities & CAPABILITY.CBOR):
    raise RuntimeError("Le périphérique ne supporte pas CTAP2/CBOR.")

ctap2 = Ctap2(dev)

seed = b"134567890123456012345678901234567890123456789012"

payload = {
    1: "user2",
    2: 2,  # 2 = TOTP
    3: {
        1: 4,        # kty = symmetric
        3: 4,        # alg = HMAC-SHA1
       -1: seed
    },
    4: 6,    # digits
    6: 30    # period
}

timestep = 30
unix_time = int(time())
T = unix_time // timestep
T_bytes = T.to_bytes(8, 'big')  # 8 octets big-endian
payload2 = {
    1: "user2",
    -1: b'\x00\x00\x00\x00\x00\x00\x00\x01'
}

#cbor_payload = encode(payload)

# 4. Envoyer une commande personnalisée
# Exemple : commande CTAP2 non attribuée (ex: 0x40 à 0xBF réservée au fabricant)
CUSTOM_CTAP_COMMAND = 0xB2

try:
    response = ctap2.send_cbor(CUSTOM_CTAP_COMMAND, payload2)
    print("Réponse du token :", response)

except Exception as e:
    print("Erreur lors de l'envoi :", e)
    cbor_payload = dumps(payload2)
    print("CBOR hex:", binascii.hexlify(cbor_payload))
