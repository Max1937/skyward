//! The functions the USB port offers, which init sets up as
//! `sys.usb.config` asks: adb while the recovery waits, with files over MTP
//! beside it while file transfer is on.

use crate::{prop, set_prop, wait_prop};
use anyhow::{ensure, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static MTP: AtomicBool = AtomicBool::new(false);

/// What the port offers while nothing else has it.
pub fn resting() -> &'static str {
    if MTP.load(Ordering::Relaxed) {
        "mtp,adb"
    } else {
        "adb"
    }
}

/// Whether MTP goes beside adb while the port rests: from when its function
/// has its descriptors until it goes.
pub fn set_mtp(on: bool) {
    MTP.store(on, Ordering::Relaxed);
}

/// Ask init for `config` and wait until it is in place. Going to "none"
/// also waits for adbd to be gone, so its function is free.
pub fn set(config: &str, timeout: Duration) -> Result<()> {
    set_prop("sys.usb.config", config)?;
    wait_prop("sys.usb.state", config, timeout)?;
    if config == "none" {
        let start = Instant::now();
        while !matches!(prop("init.svc.adbd").as_deref(), None | Some("stopped")) {
            ensure!(start.elapsed() < timeout, "adbd still runs {} ms after the port went to none", timeout.as_millis());
            thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}

/// Hand the port to `config`. A port that is to serve adb, with or without
/// file transfer beside it, is asked for directly: those functions share the
/// port with what is already there, and taking it through "none" first stops
/// adbd and unbinds the gadget, which on a phone whose init drives the older
/// port path while the port is really a configfs gadget leaves it unbound
/// with nothing to bring it back. Only a server that must have the port to
/// itself is given it through "none", which stops the programs serving it and
/// takes every function off; init then sets the port up once the programs
/// behind the new configuration are ready.
pub fn switch(config: &str, timeout: Duration) -> Result<()> {
    if takes_the_port_alone(config) {
        set("none", timeout)?;
    }
    set(config, timeout)
}

/// Whether the programs behind `config` need every function off the port
/// before they take it: adb and file transfer do not, as each waits for the
/// other's readiness flags and then binds beside it.
fn takes_the_port_alone(config: &str) -> bool {
    !matches!(config, "adb" | "mtp,adb" | "none")
}
