from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.webauthn import PublicKeyCredentialParameters
import os
import datetime

# 1. Se connecter à l'appareil
device = next(CtapHidDevice.list_devices())
ctap2 = Ctap2(device)

# 2. Client data hash : 32 octets
client_data_hash = b"seedOTP:129391291293912932789081"

# 3. Paramètres bruts (pas de classes helper)
rp = {
    "id": "yamnord.com",
    "name": "Yamnord"
}

user = {
    "id": b"2347asdf7234",
    "name": "nickray",
    "displayName": "nickray"
}

key_params = [
    {"type": "public-key", "alg": -7}  # ES256
]

# 4. Appel à make_credential avec dictionnaires natifs
attestation = ctap2.make_credential(
    client_data_hash=client_data_hash,
    rp=rp,
    user=user,
    key_params=key_params,
    options={"residentKey": "preferred", "userVerification": "discouraged"},
    on_keepalive= print("Touchez votre token pour continuer..."),
)

# 5. Résultat
auth_data = attestation.auth_data
credential_id = auth_data.credential_data.credential_id

timestamp = int(datetime.datetime.now(datetime.UTC).timestamp())
padding = b"\0"*24
client_data_hash = timestamp.to_bytes(8, byteorder="little") + padding

# 6. Construction de l'assertion
assertion_response = ctap2.get_assertion(
    rp_id="yamnord.com",
    client_data_hash=client_data_hash,
    allow_list=[{"type": "public-key", "id": credential_id}],
    options={"userVerification": False},
    on_keepalive=lambda status: print("👉 Touchez votre token pour l'assertion..."),
)

otp = str(int.from_bytes(assertion_response.signature[:8], "little")).zfill(6)

# 7. Affichage du résultat
print("✅ Assertion reçue :")
print("Signature:", assertion_response.signature.hex())
print("Code OTP :", otp)
