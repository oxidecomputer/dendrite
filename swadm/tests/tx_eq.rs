//! # Tx Eq
//!
//! This module tests CLI commands that CRUD
//! tx equalization settings on a link.

mod cmd;

use anyhow::Context;

use crate::cmd::re::{ANY, PARENS};
use serial_test::serial;

// TODO::cory
// Add a `create link` module.

/// Sets some but not all tx eq taps on a port.
/// Unspecified taps default to zero.
//
// Aside: I would prefer different semantics, but
// scripts in other repos rely on this behavior.
#[test]
#[serial]
fn set_partial_taps() -> anyhow::Result<()> {
    let port = "rear0";
    let link = "rear0/0";

    self::create_link(port, link).context("link setup failed")?;

    cmd::swadm(format!("link serdes set txeq {link} --main=-20"))?;

    let tx_eq = cmd::swadm(format!("link serdes get txeq {link}"))?;
    for (label, val) in
        [("pre2", 0), ("pre1", 0), ("main", -20), ("post1", 0), ("post2", 0)]
    {
        tx_eq.expect_line(pat![
            label, val, PARENS, val, PARENS, val, PARENS, val, PARENS
        ])?;
    }

    Ok(())
}

/// Sets tx eq when all taps on a link are declared.
#[test]
#[serial]
fn set_all_taps() -> anyhow::Result<()> {
    let port = "rear0";
    let link = "rear0/0";

    self::create_link(port, link).context("link setup failed")?;

    cmd::swadm(format!(
        "link serdes set tx-eq {link} --pre2=-1 --pre1 0 --main 10 --post1=5 --post2 2"
    ))?;

    let tx_eq = cmd::swadm(format!("link serdes get txeq {link}"))?;
    for (label, val) in
        [("pre2", -1), ("pre1", 0), ("main", 10), ("post1", 5), ("post2", 2)]
    {
        tx_eq.expect_line(pat![
            label, val, PARENS, val, PARENS, val, PARENS, val, PARENS
        ])?;
    }

    Ok(())
}

/// Creates the new link and runs a few validations on it.
fn create_link(port: &str, link: &str) -> anyhow::Result<()> {
    cmd::swadm("link ls")?
        .expect_line(pat!["Port/Link", "Media", ANY])
        .context("Is swadm usable right now?")?;

    let delete_cmd = format!("link del {link}");
    if let Err(e) = cmd::swadm(&delete_cmd) {
        println!(
            "Delete failed. This can occur when the link doesn't exist: {e:?}"
        );
    }

    cmd::swadm(format!("link create {port} -s 100g --fec rs"))?
        .expect_line(pat![format!("Created link {link}")])?;

    cmd::swadm(format!("link enable {link}"))?;

    cmd::swadm(format!("link get {link} -v"))?
        .expect_line(pat!["Speed", "100G"])?;

    Ok(())
}
