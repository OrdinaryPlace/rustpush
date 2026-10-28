//! Binary acquisition errors, independent of whether the real Apple binary is
//! installed: a missing file and a wrong-hash file at `$OPEN_ABSINTHE_BINARY`
//! yield specific error codes (and the library never downloads anything).
//!
//! This file holds exactly one test, so nothing else in this test process
//! reads the environment or has loaded (and cached) the real binary.

use std::path::PathBuf;

use open_absinthe::AbsintheError;
use open_absinthe::nac::{self, E_BAD_HASH, E_NO_BINARY, HardwareConfig, ValidationCtx};

fn set_env(key: &str, val: &std::ffi::OsStr) {
    // SAFETY: this test binary runs a single test on a single thread, so no
    // other thread can be reading or writing the environment concurrently.
    unsafe { std::env::set_var(key, val) }
}

fn hw() -> HardwareConfig {
    HardwareConfig {
        product_name: "Macmini7,1".into(),
        io_mac_address: [2, 0, 0, 0, 0, 1],
        platform_serial_number: "C02FAKE00001".into(),
        platform_uuid: "00000000-1111-2222-3333-444444444444".into(),
        root_disk_uuid: "55555555-6666-7777-8888-999999999999".into(),
        board_id: "Mac-35C5E08120C7EEAF".into(),
        os_build_num: "22F66".into(),
        platform_serial_number_enc: vec![1; 17],
        platform_uuid_enc: vec![2; 17],
        root_disk_uuid_enc: vec![3; 17],
        rom: vec![2, 0, 0, 0, 0, 1],
        rom_enc: vec![4; 17],
        mlb: "C02FAKEMLB0000001".into(),
        mlb_enc: vec![5; 17],
    }
}

#[test]
fn missing_or_wrong_binary_gives_specific_errors() {
    let dir = std::env::temp_dir().join(format!("open-absinthe-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // $XDG_DATA_HOME (Windows: %LOCALAPPDATA%) fallback when the override
    // is empty.
    set_env("OPEN_ABSINTHE_BINARY", "".as_ref());
    set_env(if cfg!(windows) { "LOCALAPPDATA" } else { "XDG_DATA_HOME" }, dir.as_os_str());
    assert_eq!(nac::binary_path(), dir.join("imessage-linux/IMDAppleServices"));

    let fake: PathBuf = dir.join("IMDAppleServices");
    set_env("OPEN_ABSINTHE_BINARY", fake.as_os_str());
    assert_eq!(nac::binary_path(), fake);

    let mut out = Vec::new();
    let r = ValidationCtx::new(b"cert", &mut out, &hw());
    assert_eq!(r.err(), Some(AbsintheError(E_NO_BINARY)));
    assert!(!fake.exists(), "the library must not download the binary");

    std::fs::write(&fake, b"definitely not IMDAppleServices").unwrap();
    let r = ValidationCtx::new(b"cert", &mut out, &hw());
    assert_eq!(r.err(), Some(AbsintheError(E_BAD_HASH)));
    assert!(out.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
