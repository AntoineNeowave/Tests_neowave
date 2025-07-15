use anyhow::{anyhow, Result};
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    Cfg, FidoKeyHidFactory, FidoKeyHid, verifier, public_key::PublicKey, public_key_credential_user_entity::PublicKeyCredentialUserEntity
};
use serde_cbor;

fn main() -> Result<()>{

    if let Some(device) = check_fido2_device() {
        println!("La clé FIDO2 détectée est prête à être utilisée.");

        match device.get_info() {
            Ok(info) => println!("Infos clés :\n{}", info),
            Err(e) => eprintln!("Erreur lors de la récupération des infos : {:?}", e),
        }

        let (credential_id, credential_pubkey) = register(&device)?;
        authenticate(&device, &credential_id, &credential_pubkey)?;
        println!("Authentification réussie !");

    } else {
        println!("Aucune clé prête détectée pour l'instant.");
    }

    Ok(())
}

fn check_fido2_device() -> Option<FidoKeyHid> {
    match FidoKeyHidFactory::create(&Cfg::init()) {
        Ok(device) => {
            println!("Found one FIDO2 device. Proceeding...");
            Some(device)
        }
        Err(e) => {
            let error_message = e.to_string();
            if error_message.contains("FIDO device not found.") {
                println!("No FIDO2 device found. Please insert your FIDO2 key.");
            } else if error_message.contains("Multiple FIDO devices found.") {
                println!("Multiple FIDO2 devices found. Please keep only one key plugged.");
            } else {
                eprintln!("Error initializing FIDO2 device: {:?}", e);
            }
            None
        }
    }
}

fn register(device: &FidoKeyHid) -> Result<(Vec<u8>, PublicKey)> {

    println!("Registering a new credential...");

    let rpid = "example.com";

    let user_data = "test donnée OTP";
    let cbor_encoded = serde_cbor::to_vec(&user_data)?;

    let challenge = cbor_encoded.clone();

    let user = PublicKeyCredentialUserEntity {
        id: cbor_encoded.clone(),
        name: "user1".to_string(),
        display_name: "OTP user".to_string(),
    };

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .user_entity(&user)
        .pin("0000")
        .resident_key()
        .build();
    let attestation = device.make_credential_with_args(&make_credential_args)?;

    // verify `Attestation` Object
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if !verify_result.is_success {
        println!("- ! Verify Failed");
        return Err(anyhow!("Attestation verification failed"));
    }

    // store Credential Id and Publickey
    Ok((verify_result.credential_id, verify_result.credential_public_key))
}

fn authenticate(
    device: &FidoKeyHid,
    userdata_credential_id: &[u8],
    userdata_credential_public_key: &PublicKey,
) -> Result<()> {

    println!("Authenticating with existing credential...");

    let rpid = "example.com";

    let user_data = "test donnée OTP";
    let cbor_encoded = serde_cbor::to_vec(&user_data)?;

    let challenge = cbor_encoded.clone();

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin("0000")
        .credential_id(userdata_credential_id)
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    //println!("✅ Résultat get_assertion :\n{:#?}", assertions);

    println!(
        "✅ User ID extrait (décodé depuis CBOR) : {:?}",
        serde_cbor::from_slice::<String>(&assertions[0].user.id)?
    );

    // verify `Assertion` Object
    if !verifier::verify_assertion(
        rpid,
        userdata_credential_public_key,
        &challenge,
        &assertions[0],
    ) {
        println!("- ! Verify Assertion Failed");
        return Err(anyhow!("Assertion verification failed"));
    }



    Ok(())
}