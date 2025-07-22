use std::convert::TryInto as _;

use ctaphid_types::VendorCommand;

const VID_NITROKEY_3: u16 = 0x1050;
const PID_NITROKEY_3: u16 = 0x0407;
const COMMAND_VERSION: VendorCommand = VendorCommand::H61;
const COMMAND_UUID: VendorCommand = VendorCommand::H62;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let hidapi = hidapi::HidApi::new()?;
    for device_info in hidapi
        .device_list()
        .filter(|device| device.vendor_id() == VID_NITROKEY_3)
        .filter(|device| device.product_id() == PID_NITROKEY_3)
    {
        let device = device_info.open_device(&hidapi)?;
        let device = ctaphid::Device::new(device, device_info.to_owned())?;

        let version = device.vendor_command(COMMAND_VERSION, &[])?;
        let version = u32::from_be_bytes(version.try_into().expect("Missing response data"));
        // version = (major << 22) | (minor << 6) | patch
        let major = version >> 22;
        let minor = (version >> 6) & 0b1111_1111_1111_1111;
        let patch = version & 0b11_1111;

        // Requires firmware version >= 1.0.1
        let uuid = if major > 1 || (major == 1 && (minor > 0 || patch > 0)) {
            let uuid = device.vendor_command(COMMAND_UUID, &[])?;
            Some(u128::from_be_bytes(
                uuid.try_into().expect("Missing response data"),
            ))
        } else {
            None
        };

        print!("{}\t", device_info.path().to_string_lossy());
        if let Some(uuid) = uuid {
            print!("{:X}", uuid);
        } else {
            print!("{: <32}", "[unknown UUID]");
        }
        println!("\tv{}.{}.{}", major, minor, patch);
    }
    Ok(())
}