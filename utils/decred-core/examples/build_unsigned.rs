// SPDX-FileCopyrightText: 2026 The Decred developers
// SPDX-License-Identifier: Apache-2.0
//! Build a small single-input unsigned-tx package (`unsigned.dcrtx`) for
//! exercising the SD-card signing flow end to end.
//!
//! Derives the input from the same known test entropy `sign_it.rs` uses, so the
//! produced package is signable by a device restored from that seed. Format
//! version 3 requires each input's funding transaction PREFIX (dcrd
//! `TxSerializeNoWitness`) — the device recomputes blake256 over it and demands
//! it equal `prev_hash`, which is what turns `value_in` from a companion
//! assertion into verified evidence. A real spend carries the real funding
//! transaction; this builds a synthetic one and takes `prev_hash` from it, so
//! the package is self-consistent by construction but is NOT a spend of any
//! on-chain coin.

use decred_core::address::{p2pkh_script, Address, AddressKind};
use decred_core::airgap::{encode_sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION};
use decred_core::hashing::hash160;
use decred_core::hd::{ExtPrivKey, BRANCH_EXTERNAL};
use decred_core::secp256k1::Secp256k1;
use decred_core::tx::{MsgTx, TxOut};
use decred_core::Network;

const ENTROPY_HEX: &str = "348360ae0a69b1883b0dfc060136108dfcabe9f4bf8af3e866b742fb53f1caa5";

fn main() {
    let secp = Secp256k1::new();
    let master = ExtPrivKey::from_entropy(&hex_to_bytes(ENTROPY_HEX), "", Network::Mainnet).expect("master");
    let account = master.account_key(&secp, 0).expect("account key");

    // Input: our own external/0 key, so the device's ownership proof passes.
    let key0 = account.address_key(&secp, BRANCH_EXTERNAL, 0).expect("addr key 0");
    let prev_script = p2pkh_script(&hash160(&key0.compressed_pubkey(&secp))).to_vec();

    let funding = MsgTx {
        version: 1,
        tx_in: Vec::new(),
        tx_out: vec![TxOut { value: 100_000, version: 0, pk_script: prev_script.clone() }],
        lock_time: 0,
        expiry: 0,
    };
    let prev_hash = funding.tx_hash();

    let input = InputMeta {
        prev_hash,
        prev_index: 0,
        tree: 0,
        sequence: 0xffff_ffff,
        value_in: 100_000,
        branch: BRANCH_EXTERNAL,
        index: 0,
        prev_script,
        prev_tx_prefix: Some(funding.serialize_prefix()),
    };

    let dest = "Dsj4BQDcu3xNCTNMwvBbCigQcWiRFaNqaKK";
    let addr = Address::decode(dest).expect("decode dest address");
    assert_eq!(addr.kind, AddressKind::P2pkh, "P2PKH destinations only");
    let recipient = OutputMeta {
        value: 60_000,
        version: 0,
        pk_script: p2pkh_script(&addr.hash).to_vec(),
        is_change: false,
        branch: None,
        index: None,
    };

    // Change back to our own external/1, carrying the path that proves it.
    let key1 = account.address_key(&secp, BRANCH_EXTERNAL, 1).expect("addr key 1");
    let change = OutputMeta {
        value: 37_460,
        version: 0,
        pk_script: p2pkh_script(&hash160(&key1.compressed_pubkey(&secp))).to_vec(),
        is_change: true,
        branch: Some(BRANCH_EXTERNAL),
        index: Some(1),
    };

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![input],
        outputs: vec![recipient, change],
        account_fp: Some(account.neuter(&secp).fingerprint()),
    };
    // Prove the package is actually reviewable before writing it out — a
    // fixture that fails validate() wastes a trip to the device.
    req.validate().expect("package must validate");

    let bytes = encode_sign_request(&req).expect("encode");
    std::fs::write("unsigned.dcrtx", &bytes).expect("write file");
    println!("wrote unsigned.dcrtx ({} bytes, format version {FORMAT_VERSION})", bytes.len());
    println!("  input:   100000 atoms  (synthetic funding tx, vout 0)");
    println!("  output:   60000 atoms -> {dest}");
    println!("  change:   37460 atoms -> our own m/44'/42'/0'/0/1");
    println!("  fee:       2540 atoms");
    println!("\nSignable by a device restored from the test entropy {ENTROPY_HEX}");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
