use hidapi::HidApi;
use std::time::Duration;
use std::thread::sleep;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialisation de l'API HID
    let api = HidApi::new()?;

    // Affichage des périphériques connectés
    for device in api.device_list() {
        println!(
            "Device: VID={:04x}, PID={:04x}, Manufacturer={:?}, Product={:?}",
            device.vendor_id(),
            device.product_id(),
            device.manufacturer_string(),
            device.product_string()
        );
    }

    // Remplace ces identifiants par ceux de ta clé FIDO
    let vendor_id = 0x1050;
    let product_id = 0x0407;

    // Ouverture du périphérique
    let device = api.open(vendor_id, product_id)?;

    // Exemple d'envoi d'une commande "otp"
    // Rapport HID : premier octet = identifiant du rapport (0x00), suivi de la charge utile
    let mut report: [u8; 65] = [0u8; 65];
    report[0] = 0x00; // Report ID
    report[1..4].copy_from_slice(b"otp"); // Commande personnalisée

    // Exemple : données (e.g. "algo:sha1;seed:base32...")
    let payload = b"algo:sha1;seed:JBSWY3DPEHPK3PXP";
    let payload_len = payload.len().min(61); // 65 - 1 (report ID) - 3 (commande)
    report[4..(4 + payload_len)].copy_from_slice(&payload[..payload_len]);

    println!("Envoi de la commande personnalisée à la clé...");
    device.write(&report)?;
    println!("Commande envoyée : {:02x?}", &report[..]);

    // Pause pour laisser le temps à la clé de traiter
    sleep(Duration::from_millis(100));

    // Lecture de la réponse
    let mut response = [0u8; 65];

    match device.read_timeout(&mut response, 500) { // Timeout 500ms
        Ok(bytes_read) => {
            println!("Réponse de la clé ({} octets) :", bytes_read);
            println!("{:?}", &response[..bytes_read]);
        }
        Err(e) => {
            println!("Aucune réponse reçue dans le délai imparti : {}", e);
        }
    }

    Ok(())
}
