from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions
import os
from fido2.pcsc import CtapPcscDevice
from exampleutils import get_client
from fido2.server import Fido2Server
import base64
from pprint import pprint



dev = next(CtapPcscDevice.list_devices(), None)
if not dev:
    raise RuntimeError("Aucun token FIDO2 détecté")

client, info = get_client()
print("Extensions supported by device:", info.extensions)

uv = "discouraged"

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

payload= b"seedOTP:12309812939129391291293912932789081"
user_id_encoded=base64.b64encode(payload)
user = {"id": payload, "name": "User test"}


# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
    challenge=payload,
    )

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {
            "otp": True
        },
    }
)

auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]
response = result.response
print("CLIENT DATA 1:", response.client_data) #objet json encodé en b64, envoyé par le client, contient des métadonnées sur la requête

# request_options, state = server.authenticate_begin(
#     credentials, 
#     user_verification=uv, 
#     challenge=payload
# )

# # Authenticate the credential
# results = client.get_assertion(
#     {
#         **request_options["publicKey"],
#         "extensions": {
#             "otp": True
#             },
#     }
# )
# result = results.get_response(0)

# server.authenticate_complete(state, credentials, result)
# response = result.response

# print("CLIENT DATA :", response.client_data)
# print()
# #print("AUTH DATA:", response.authenticator_data)
