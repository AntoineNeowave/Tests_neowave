# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and authenticates the credential.
This works with both FIDO 2.0 devices as well as with U2F devices.
On Windows, the native WebAuthn API will be used.
"""
import base64
import sys
import os

import cbor2
from exampleutils import get_client
from fido2.server import Fido2Server
from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY, CtapHidDevice
from fido2.cbor import decode, encode
from pprint import pprint
from fido2.client import AttestationObject
from fido2.client import Fido2Client
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.ctap import CtapError
from fido2.pcsc import CtapPcscDevice


# ==== 0. INFORMATIONS SUR LA CLE ====

def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


for dev in enumerate_devices():
    print("CONNECT: %s" % dev)
    print("Product name: %s" % dev.product_name)
    print("Serial number: %s" % dev.serial_number)
    print("CTAPHID protocol version: %d" % dev.version)       
    dev.close()

# ==== 1. Récupérer la clé FIDO2 connectée ====
client, info = get_client()

print("Extensions supported by device:", info.extensions)

# Préférer sans code PIN
uv = "discouraged"

# ==== 2. Définir l'identité du site (RP) ====
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
            "hmacCreateSecret": True,
            "otp": "SEEDOTP:00000000000000000000000000"
        },
    }
)


print("=== EXTENSIONS DANS LA RÉPONSE DE CRÉATION ===")
print("Client Extension Results:", result.client_extension_results)
if hasattr(result.client_extension_results, '__dict__'):
    print("Extensions détaillées:", vars(result.client_extension_results))


# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

# HmacSecret result:
if result.client_extension_results.get("hmacCreateSecret"):
    print("New credential created, with HmacSecret")
else:
    # This fails on Windows, but we might still be able to use hmac-secret even if
    # the credential wasn't made with it, so keep going
    print("Failed to create credential with HmacSecret, it might not work")

# Generate a salt for HmacSecret:
salt = os.urandom(32)
print("Authenticate with salt:", salt.hex())

print("New credential created!")
response = result.response

print("CLIENT DATA 1:", response.client_data) #objet json encodé en b64, envoyé par le client, contient des métadonnées sur la requête
#print("ATTESTATION OBJECT:", response.attestation_object) #objet binaire CBOR encodé contenant les données d'authentification etc.
print()
#print("CREDENTIAL DATA:", auth_data.credential_data) #détails sur la clé d'identitée



# Prepare parameters for getAssertion

request_options, state = server.authenticate_begin(
    credentials, 
    user_verification=uv, 
    challenge=payload
)

# Authenticate the credential
results = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            "hmacGetSecret": {"salt1": salt},
            "otp": "SEEDOTP:0000000000000000000000"
            },
    }
)

print("=== EXTENSIONS DANS LA RÉPONSE D'AUTHENTIFICATION ===")
print("Client Extension Results:", result.client_extension_results)
if hasattr(result.client_extension_results, '__dict__'):
    print("Extensions détaillées:", vars(result.client_extension_results))

# Only one cred in allowCredentials, only one response.
result = results.get_response(0)

output1 = result.client_extension_results.hmac_get_secret.output1
print("Authenticated, secret:", output1.hex())

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print("Authenticate with second salt:", salt2.hex())

# The first salt is reused, which should result in the same secret.

results = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            "hmacGetSecret": {"salt1": salt, "salt2": salt2},
            "otp": "SEEDOTP:0000000000"
            },
    }
)

# Only one cred in allowCredentials, only one response.
result = results.get_response(0)

output = result.client_extension_results.hmac_get_secret
print("Old secret:", output.output1.hex())
print("New secret:", output.output2.hex())

# Complete authenticator
server.authenticate_complete(state, credentials, result)

print("Credential authenticated!")

uh = result.response.user_handle
if uh:
    print("User Handle (ID):", uh)
else:
    print("Pas de user_handle dans la réponse.")

response = result.response

print("CLIENT DATA 3:", response.client_data)
print()
#print("AUTH DATA:", response.authenticator_data)
print("CREATE OPTION\n")
pprint(create_options["publicKey"])

print("\nREQUEST OPTION\n")
pprint(request_options["publicKey"])


