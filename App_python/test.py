from fido2.ctap2 import Ctap2
from fido2.pcsc import CtapPcscDevice, CAPABILITY
from time import time

OTP_GENERATE = 0xB2

dev = next(CtapPcscDevice.list_devices(), None)
ctap2 = Ctap2(dev)

label = "user_totp"
T = int(time()) // 30
payload = {
    1: label,
    2: T.to_bytes(8, 'big')
}

print("📤 CBOR:", payload)
resp = ctap2.send_cbor(OTP_GENERATE, payload)
print("✅ Réponse :", resp)
