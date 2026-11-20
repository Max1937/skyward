//! The functions the USB port offers, which init sets up as
//! `sys.usb.config` asks: adb while the recovery waits, with files over MTP
//! beside it while file transfer is on.

use crate::{prop, set_prop, wait_prop};
use anyhow::{ensure, Context, Result};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// The port's gadget: the functions it offers, the description it carries to
/// the computer, and the controller it is bound to.
const GADGET: &str = "/config/usb_gadget/g1";

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

/// Bind the port so that it offers file transfer beside adb, or, with `on`
/// false, so that it offers adb alone again.
///
/// The kernel reads a gadget's functions and the description it carries only
/// when the port binds, so a function added to or taken off the configuration
/// while the port is up is never seen by the computer: the port has to be
/// taken down and bound again. adb's own descriptors go with the port, so
/// adbd is stopped and started again to write them afresh. If the port is
/// left down by anything here, a waiting thread binds it again so that adb
/// comes back on its own.
pub fn bind_file_transfer(on: bool, timeout: Duration) -> Result<()> {
    let udc = format!("{GADGET}/UDC");
    let controller = fs::read_to_string(&udc).with_context(|| format!("read {udc}"))?.trim().to_string();
    ensure!(!controller.is_empty() && controller != "none", "the port is not bound to a controller");
    let config = format!("{GADGET}/configs/b.1");
    let wanted = if on { "mtp,adb" } else { "adb" };
    // Take the port down: its functions are read again when it binds.
    fs::write(&udc, "").with_context(|| format!("take the port down through {udc}"))?;
    // File transfer takes the second function, adb the first.
    let _ = fs::remove_file(format!("{config}/f2"));
    if on {
        std::os::unix::fs::symlink(format!("{GADGET}/functions/ffs.mtp"), format!("{config}/f2"))
            .with_context(|| "put the file transfer function in the port")?;
    }
    let _ = std::os::unix::fs::symlink(format!("{GADGET}/functions/ffs.adb"), format!("{config}/f1"));
    // The product the port names itself by tells the computer what it offers:
    // the recovery's own id with adb alone, and the file transfer id with it.
    let product = if on {
        "0x4EE2".to_string()
    } else {
        let adb = prop("ro.recovery.usb.adb.pid").unwrap_or_default();
        let adb = adb.trim().trim_start_matches("0x").trim_start_matches("0X");
        if adb.is_empty() { "0xD001".to_string() } else { format!("0x{adb}") }
    };
    fs::write(format!("{GADGET}/idProduct"), &product).with_context(|| format!("name the port in {GADGET}"))?;
    // adbd writes adb's descriptors as it starts, so it is started again now
    // that the port is to offer what it should.
    set_prop("ctl.stop", "adbd")?;
    let stopped = Instant::now();
    while prop("init.svc.adbd").as_deref() == Some("running") {
        ensure!(stopped.elapsed() < timeout, "adbd does not stop");
        thread::sleep(Duration::from_millis(20));
    }
    set_prop("ctl.start", "adbd")?;
    // If the port is still down after a while, bind it anyway: whatever went
    // wrong, adb is not left off the port.
    {
        let (udc, controller) = (udc.clone(), controller.clone());
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(15));
            let down = fs::read_to_string(&udc).map(|text| text.trim().is_empty()).unwrap_or(false);
            if down {
                let _ = fs::write(&udc, controller);
            }
        });
    }
    // init binds the port once adbd has written its descriptors.
    let started = Instant::now();
    while started.elapsed() < timeout {
        if fs::read_to_string(&udc).map(|text| !text.trim().is_empty()).unwrap_or(false) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    // The port is up; say what it offers, so that what waits on the state
    // sees it.
    set_prop("sys.usb.config", wanted)?;
    set_prop("sys.usb.state", wanted)?;
    Ok(())
}
