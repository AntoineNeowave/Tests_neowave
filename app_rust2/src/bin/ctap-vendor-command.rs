use hidapi::HidApi;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;
use rand::Rng;
use std::thread;
use std::time::Duration;

// Constantes CTAP-HID
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_CUSTOM: u8 = 0x40; // Commande personnalisée
const BROADCAST_CID: u32 = 0xFFFFFFFF;

fn main() -> anyhow::Result<()> {
    // 1. Détecter la clé FIDO2
    let api = HidApi::new()?;
    let device = find_fido_device(&api)?;

    println!("Clé FIDO2 détectée et ouverte");

    // 2. Diagnostics supplémentaires
    println!("=== Diagnostics du périphérique ===");
    
    // Vérifier les capacités du périphérique
    match device.get_feature_report(&mut [0u8; 64]) {
        Ok(len) => println!("Feature report disponible ({} bytes)", len),
        Err(e) => println!("Feature report non disponible: {:?}", e),
    }

    // 3. Initialisation CTAP-HID avec plusieurs tentatives
    println!("=== Initialisation CTAP-HID ===");
    let channel_id = init_ctap_hid_with_retry(&device)?;
    println!("Canal CTAP-HID initialisé : 0x{:08X}", channel_id);

    // 4. Test avec PING d'abord
    println!("=== Test PING ===");
    let ping_data = b"Hello FIDO2!";
    send_ctap_command(&device, channel_id, CTAPHID_PING, ping_data)?;
    
    let ping_response = read_ctap_response(&device, channel_id)?;
    println!("Réponse PING ({} bytes): {:?}", ping_response.len(), ping_response);
    
    if ping_response == ping_data {
        println!("✅ PING réussi ! Le protocole CTAP-HID fonctionne.");
    } else {
        println!("❌ PING échoué - réponse différente de l'envoi");
    }

    // 5. Test avec commande personnalisée
    println!("\n=== Test commande personnalisée ===");
    
    // Créer payload CBOR personnalisé
    let mut map = BTreeMap::new();
    map.insert(Value::Text("cmd".into()), Value::Text("generateOTP".into()));
    map.insert(Value::Text("time".into()), Value::Integer(1720000000));
    let cbor_payload = to_vec(&Value::Map(map))?;

    // Envoyer commande personnalisée
    send_ctap_command(&device, channel_id, CTAPHID_CUSTOM, &cbor_payload)?;

    // Lire la réponse avec timeout
    match read_ctap_response_with_timeout(&device, channel_id, 5000) {
        Ok(response) => {
            println!("Réponse commande personnalisée ({} bytes): {:?}", response.len(), response);
            
            if !response.is_empty() {
                // Tenter de décoder en CBOR
                let cbor_data = if response.len() > 1 && response[0] == 0x00 {
                    &response[1..]
                } else {
                    &response
                };

                match serde_cbor::from_slice::<Value>(cbor_data) {
                    Ok(decoded) => println!("✅ Réponse CBOR décodée : {:?}", decoded),
                    Err(e) => {
                        println!("❌ Erreur décodage CBOR : {:?}", e);
                        if let Ok(text) = std::str::from_utf8(cbor_data) {
                            println!("Réponse en texte : {}", text);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ Pas de réponse à la commande personnalisée : {:?}", e);
            println!("(Normal si le firmware ne supporte pas cette commande)");
        }
    }

    Ok(())
}

fn init_ctap_hid_with_retry(device: &hidapi::HidDevice) -> anyhow::Result<u32> {
    // Essayer plusieurs fois avec différentes approches
    for attempt in 1..=3 {
        println!("Tentative d'initialisation #{}", attempt);
        
        match init_ctap_hid_attempt(device, attempt) {
            Ok(channel_id) => return Ok(channel_id),
            Err(e) => {
                println!("Tentative {} échouée: {:?}", attempt, e);
                if attempt < 3 {
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Toutes les tentatives d'initialisation ont échoué"))
}

fn init_ctap_hid_attempt(device: &hidapi::HidDevice, attempt: u8) -> anyhow::Result<u32> {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill(&mut nonce);

    let mut packet = [0u8; 65]; // 1 report ID + 64 data
    packet[0] = 0x00; // Report ID
    packet[1..5].copy_from_slice(&BROADCAST_CID.to_be_bytes());
    packet[5] = CTAPHID_INIT;
    packet[6..8].copy_from_slice(&(nonce.len() as u16).to_be_bytes());
    packet[8..16].copy_from_slice(&nonce);

    println!("Nonce: {:02X?}", nonce);
    device.write(&packet)?;

    let mut response = [0u8; 65];
    let len = device.read_timeout(&mut response, match attempt {
        1 => 2000,
        2 => 5000,
        _ => 10000,
    })?;

    if len < 19 {
        return Err(anyhow::anyhow!("Réponse d'initialisation trop courte: {} bytes", len));
    }

    let data = &response[1..]; // skip Report ID

    if data[4] != CTAPHID_INIT {
        return Err(anyhow::anyhow!("Réponse d'initialisation invalide, commande: 0x{:02X}", data[4]));
    }

    if data[7..15] != nonce {
        return Err(anyhow::anyhow!("Nonce invalide dans la réponse"));
    }

    let channel_id = u32::from_be_bytes([data[15], data[16], data[17], data[18]]);
    Ok(channel_id)
}


fn send_ctap_command(
    device: &hidapi::HidDevice,
    channel_id: u32,
    command: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut packet = [0u8; 65];
    packet[0] = 0x00; // Report ID
    packet[1..5].copy_from_slice(&channel_id.to_be_bytes());
    packet[5] = command;
    packet[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());

    let payload_size = std::cmp::min(payload.len(), 57);
    packet[8..8 + payload_size].copy_from_slice(&payload[..payload_size]);
    device.write(&packet)?;

    if payload.len() > 57 {
        let mut offset = 57;
        let mut seq = 0u8;

        while offset < payload.len() {
            let mut cont_packet = [0u8; 65];
            cont_packet[0] = 0x00; // Report ID
            cont_packet[1..5].copy_from_slice(&channel_id.to_be_bytes());
            cont_packet[5] = seq;

            let chunk_size = std::cmp::min(59, payload.len() - offset);
            cont_packet[6..6 + chunk_size].copy_from_slice(&payload[offset..offset + chunk_size]);

            device.write(&cont_packet)?;
            offset += chunk_size;
            seq += 1;
        }
    }

    Ok(())
}


fn read_ctap_response(device: &hidapi::HidDevice, channel_id: u32) -> anyhow::Result<Vec<u8>> {
    read_ctap_response_with_timeout(device, channel_id, 1000)
}

fn read_ctap_response_with_timeout(
    device: &hidapi::HidDevice,
    channel_id: u32,
    timeout_ms: i32,
) -> anyhow::Result<Vec<u8>> {
    device.set_blocking_mode(false)?;

    let mut response = [0u8; 65];
    let len = device.read_timeout(&mut response, timeout_ms)?;
    if len < 8 {
        return Err(anyhow::anyhow!("Réponse trop courte"));
    }

    let data = &response[1..]; // Ignore Report ID
    let resp_channel_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if resp_channel_id != channel_id {
        return Err(anyhow::anyhow!("Channel ID invalide dans la réponse"));
    }

    let command = data[4];
    if command & 0x80 != 0 {
        let error_code = if len > 8 { data[7] } else { 0 };
        return Err(anyhow::anyhow!("Erreur CTAP-HID : commande 0x{:02X}, code 0x{:02X}", command, error_code));
    }

    let payload_len = u16::from_be_bytes([data[5], data[6]]) as usize;
    let mut payload = Vec::new();

    let first_chunk_size = std::cmp::min(payload_len, 57);
    payload.extend_from_slice(&data[7..7 + first_chunk_size]);

    let mut remaining = payload_len - first_chunk_size;
    let mut seq = 0u8;

    while remaining > 0 {
        let len = device.read_timeout(&mut response, timeout_ms)?;
        if len < 6 {
            return Err(anyhow::anyhow!("Paquet de continuation trop court"));
        }

        let data = &response[1..];
        let resp_channel_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if resp_channel_id != channel_id || data[4] != seq {
            return Err(anyhow::anyhow!("Paquet de continuation invalide"));
        }

        let chunk_size = std::cmp::min(remaining, 59);
        payload.extend_from_slice(&data[5..5 + chunk_size]);
        remaining -= chunk_size;
        seq += 1;
    }

    Ok(payload)
}


fn find_fido_device(api: &HidApi) -> anyhow::Result<hidapi::HidDevice> {
    // Identifiants HID communs pour les clés FIDO2
    const FIDO_USAGE_PAGE: u16 = 0xF1D0;
    const FIDO_USAGE: u16 = 0x01;
    
    println!("Recherche des périphériques FIDO2...");
    
    for device_info in api.device_list() {
        println!("Device trouvé: VID={:04X} PID={:04X} Usage={:04X} UsagePage={:04X} Interface={:?} {} {}", 
            device_info.vendor_id(), 
            device_info.product_id(),
            device_info.usage(),
            device_info.usage_page(),
            device_info.interface_number(),
            device_info.manufacturer_string().unwrap_or("Inconnu"),
            device_info.product_string().unwrap_or("Inconnu"));
            
        if device_info.usage_page() == FIDO_USAGE_PAGE && device_info.usage() == FIDO_USAGE {
            println!("✅ Clé FIDO2 sélectionnée : {} {}", 
                device_info.manufacturer_string().unwrap_or("Inconnu"),
                device_info.product_string().unwrap_or("Inconnu"));
            return Ok(device_info.open_device(api)?);
        }
    }
    
    Err(anyhow::anyhow!("Aucune clé FIDO2 trouvée"))
}