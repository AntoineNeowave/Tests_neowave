# Modifiez votre exampleutils.py avec cette version plus détaillée

import ctypes
from getpass import getpass
import json
import binascii

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.extensions import Ctap2Extension

# Support NFC devices if we can
try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

from fido2.ctap2.extensions import Ctap2Extension, RegistrationExtensionProcessor, AuthenticationExtensionProcessor

class MyExtension(Ctap2Extension):
    NAME = "otp"
    
    def is_supported(self, ctap):
        print(f"=== MyExtension.is_supported ===")
        print(f"CTAP Info: {ctap.info}")
        print(f"Extensions supportées: {getattr(ctap.info, 'extensions', [])}")
        supported = self.NAME in getattr(ctap.info, 'extensions', [])
        print(f"Extension '{self.NAME}' supportée: {supported}")
        return True  # On retourne True pour tester même si non supportée
    
    def make_credential(self, ctap, options, pin_protocol):
        print(f"=== MyExtension.make_credential ===")
        print(f"Options reçues: {options}")
        print(f"Pin protocol: {pin_protocol}")
        
        processor = MyRegistrationExtensionProcessor()
        return processor
    
    def get_assertion(self, ctap, options, pin_protocol):
        print(f"=== MyExtension.get_assertion ===")
        print(f"Options reçues: {options}")
        print(f"Pin protocol: {pin_protocol}")
        
        processor = MyAuthenticationExtensionProcessor()
        return processor

class MyRegistrationExtensionProcessor(RegistrationExtensionProcessor):
    def __init__(self):
        print(f"=== MyRegistrationExtensionProcessor.__init__ ===")
        super().__init__(
            inputs={"otp": True},
            outputs={"otp": True}
        )
    
    def prepare_inputs(self, pin_token):
        print(f"=== MyRegistrationExtensionProcessor.prepare_inputs ===")
        print(f"Pin token: {pin_token}")
        inputs = {"otp": True}
        print(f"Inputs préparés pour l'authenticateur: {inputs}")
        return inputs
    
    def process_create_response(self, response):
        """Traite la réponse de l'authenticateur après création"""
        print(f"=== MyRegistrationExtensionProcessor.process_create_response ===")
        print(f"Type de réponse: {type(response)}")
        print(f"Réponse complète: {response}")
        
        # Examiner les données brutes
        if hasattr(response, 'extension_results'):
            print(f"Extension results dans la réponse: {response.extension_results}")
        
        # Essayer d'accéder aux données CTAP brutes
        if hasattr(response, 'authenticator_data'):
            print(f"Authenticator data: {response.authenticator_data}")
            if hasattr(response.authenticator_data, 'extensions'):
                print(f"Extensions dans authenticator_data: {response.authenticator_data.extensions}")
        
        # Par défaut, retourner ce qu'on a défini
        result = {"otp": True}
        print(f"Résultat final pour le client: {result}")
        return result

class MyAuthenticationExtensionProcessor(AuthenticationExtensionProcessor):
    def __init__(self):
        print(f"=== MyAuthenticationExtensionProcessor.__init__ ===")
        super().__init__(
            inputs={"otp": True},
            outputs={"otp": True}
        )
    
    def prepare_inputs(self, selected, pin_token):
        print(f"=== MyAuthenticationExtensionProcessor.prepare_inputs ===")
        print(f"Selected credential: {selected}")
        print(f"Pin token: {pin_token}")
        inputs = {"otp": True}
        print(f"Inputs préparés pour l'authenticateur: {inputs}")
        return inputs
    
    def process_get_response(self, response):
        """Traite la réponse de l'authenticateur après authentification"""
        print(f"=== MyAuthenticationExtensionProcessor.process_get_response ===")
        print(f"Type de réponse: {type(response)}")
        print(f"Réponse complète: {response}")
        
        # Examiner les données brutes
        if hasattr(response, 'extension_results'):
            print(f"Extension results dans la réponse: {response.extension_results}")
        
        if hasattr(response, 'authenticator_data'):
            print(f"Authenticator data: {response.authenticator_data}")
            if hasattr(response.authenticator_data, 'extensions'):
                print(f"Extensions dans authenticator_data: {response.authenticator_data.extensions}")
        
        # Par défaut, retourner ce qu'on a défini
        result = {"otp": True}
        print(f"Résultat final pour le client: {result}")
        return result

# Handle user interaction via CLI prompts
class CliInteraction(UserInteraction):
    def __init__(self):
        self._pin = None

    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev

def get_client(predicate=None, **kwargs):
    user_interaction = kwargs.pop("user_interaction", None) or CliInteraction()

    # Locate a device
    for dev in enumerate_devices():
        client = Fido2Client(
            dev,
            client_data_collector=DefaultClientDataCollector("https://example.com"),
            user_interaction=user_interaction,
            **kwargs,
            extensions=[HmacSecretExtension(allow_hmac_secret=True), MyExtension()],
        )
        if predicate is None or predicate(client.info):
            return client, client.info
    else:
        raise ValueError("No suitable Authenticator found!")