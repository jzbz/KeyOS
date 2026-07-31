// SPDX-License-Identifier: Apache-2.0
//! Sign a single-input request with a known test seed and print the resulting
//! transaction hex. Companion piece to `build_unsigned.rs` for exercising the
//! airgap format outside the device.
//!
//! Format version 3 requires each input's funding transaction PREFIX, so the
//! funding transaction is now part of the request rather than a bare txid.
//! Pass one on the command line to spend a REAL coin:
//!
//! ```text
//! cargo run -p decred-core --example sign_it -- <funding-tx-prefix-hex> [vout]
//! ```
//!
//! With no argument it builds a synthetic funding transaction paying our own
//! external/0 key, which exercises the whole signer end to end but produces a
//! transaction that spends a coin that does not exist — do not try to broadcast
//! it.

use decred_core::address::{p2pkh_script, Address, AddressKind};
use decred_core::airgap::{sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION};
use decred_core::hashing::hash160;
use decred_core::hd::{ExtPrivKey, BRANCH_EXTERNAL};
use decred_core::secp256k1::Secp256k1;
use decred_core::tx::{MsgTx, TxOut};
use decred_core::Network;

fn main() {
    let entropy_hex = "348360ae0a69b1883b0dfc060136108dfcabe9f4bf8af3e866b742fb53f1caa5";
    let entropy = hexb(entropy_hex);

    let secp = Secp256k1::new();
    let master = ExtPrivKey::from_entropy(&entropy, "", Network::Mainnet).expect("master");

    // sanity: derive the funding address, must match DsSXAf...
    // (This seed's account key is identical under dcrd's hardened derivation
    // and strict BIP32 — it has no leading-zero step — so this assertion is
    // stable across the 0.4.0 derivation fix.)
    let acct = master.account_key(&secp, 0).unwrap();
    let k = acct.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let addr = k.p2pkh_address(&secp);
    println!("derived addr: {addr}");
    assert_eq!(addr, "DsSXAfxCeGfPgWEHKLmp6HQJJJDvJFDPfFL", "ADDRESS MISMATCH");
    println!("address matches funding address — correct seed confirmed");

    let our_script = p2pkh_script(&hash160(&k.compressed_pubkey(&secp))).to_vec();

    // Funding transaction: supplied on the command line, or synthesized.
    let args: Vec<String> = std::env::args().collect();
    let (prev_tx_prefix, prev_index, real) = match args.get(1) {
        Some(hex) => {
            let raw = hexb(hex);
            let vout: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            MsgTx::parse_prefix(&raw)
                .expect("argument must be a PREFIX serialization (TxSerializeNoWitness)");
            (raw, vout, true)
        }
        None => {
            let funding = MsgTx {
                version: 1,
                tx_in: Vec::new(),
                tx_out: vec![TxOut { value: 100_000, version: 0, pk_script: our_script.clone() }],
                lock_time: 0,
                expiry: 0,
            };
            (funding.serialize_prefix(), 0, false)
        }
    };

    let funding = MsgTx::parse_prefix(&prev_tx_prefix).expect("parse funding prefix");
    let out = funding.tx_out.get(prev_index as usize).expect("vout past end of funding tx");
    let value_in = out.value;
    let prev_script = out.pk_script.clone();
    if prev_script != our_script {
        eprintln!(
            "WARNING: funding output {prev_index} does not pay our external/0 key — signing will refuse"
        );
    }

    let input = InputMeta {
        prev_hash: funding.tx_hash(),
        prev_index,
        tree: 0,
        sequence: 0xffff_ffff,
        value_in,
        branch: BRANCH_EXTERNAL,
        index: 0,
        prev_script,
        prev_tx_prefix: Some(prev_tx_prefix),
    };

    // output: value_in minus a 2540-atom fee -> Dsj4...
    let dest = "Dsj4BQDcu3xNCTNMwvBbCigQcWiRFaNqaKK";
    let dest_addr = Address::decode(dest).unwrap();
    assert_eq!(dest_addr.kind, AddressKind::P2pkh);
    let output = OutputMeta {
        value: value_in - 2_540,
        version: 0,
        pk_script: p2pkh_script(&dest_addr.hash).to_vec(),
        is_change: false,
        branch: None,
        index: None,
    };

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![input],
        outputs: vec![output],
        account_fp: None,
    };

    let signed = sign_request(&secp, &master, &req).expect("SIGN FAILED");
    let signed_hex: String = signed.iter().map(|b| format!("{b:02x}")).collect();
    println!("\n=== SIGNED TX HEX ===");
    println!("{signed_hex}");
    std::fs::write("signed_tx.hex", &signed_hex).ok();
    println!("\n(saved to ./signed_tx.hex)");
    if real {
        println!("Funding transaction supplied — this spends a real coin, broadcast when ready.");
    } else {
        println!("SYNTHETIC funding transaction — this spends a coin that does not exist.");
        println!("Pass a real funding-tx prefix hex as argv[1] to produce a broadcastable tx.");
    }
}

fn hexb(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
