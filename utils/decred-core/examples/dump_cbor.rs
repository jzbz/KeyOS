// SPDX-FileCopyrightText: 2026 The Decred developers
// SPDX-License-Identifier: Apache-2.0
//! Print the CBOR bytes of a reference format-version-3 SignRequest, annotated
//! with the array layout — the quickest way to eyeball what a companion wallet
//! must emit.

use decred_core::airgap::{encode_sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION};
use decred_core::hd::BRANCH_EXTERNAL;
use decred_core::tx::{MsgTx, TxOut};

fn main() {
    let script = hex::decode("76a914c671a001f211d63e0b0b4791e6d343c85b1e72f088ac").unwrap();

    // Version 3 requires the funding transaction's PREFIX serialization
    // (dcrd TxSerializeNoWitness) per input: the device recomputes blake256
    // over it, demands it equal prev_hash, and demands the referenced output
    // carry exactly the declared value_in and prev_script. Building the funding
    // tx here and taking prev_hash from it keeps the sample self-consistent.
    let funding = MsgTx {
        version: 1,
        tx_in: Vec::new(),
        tx_out: vec![TxOut { value: 94_000, version: 0, pk_script: script.clone() }],
        lock_time: 0,
        expiry: 0,
    };

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: funding.tx_hash(),
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 94_000,
            branch: BRANCH_EXTERNAL,
            index: 1,
            prev_script: script.clone(),
            prev_tx_prefix: Some(funding.serialize_prefix()),
        }],
        outputs: vec![
            OutputMeta {
                value: 60_000,
                version: 0,
                pk_script: hex::decode("76a914424242424242424242424242424242424242424288ac").unwrap(),
                is_change: false,
                branch: None,
                index: None,
            },
            // A change output must carry the path that proves it is ours, and
            // `is_change` must agree with that path's presence — a package where
            // the two disagree is malformed and refused.
            OutputMeta {
                value: 31_830,
                version: 0,
                pk_script: script,
                is_change: true,
                branch: Some(BRANCH_EXTERNAL),
                index: Some(1),
            },
        ],
        account_fp: None,
    };
    let bytes = encode_sign_request(&req).unwrap();
    println!("=== CBOR SignRequest (format version {FORMAT_VERSION}), {} bytes ===", bytes.len());
    println!("{}", hex::encode(&bytes));
    println!();
    println!("ARRAY-encoded (minicbor default, no #[cbor(map)]):");
    println!("  SignRequest = 7-element CBOR array (8 when account_fp is present)");
    println!("  inputs[i]   = 9-element CBOR array (prev_tx_prefix is the 9th)");
    println!("  outputs[i]  = 6-element CBOR array (branch + index are 5th and 6th)");
    println!();
    println!("Byte-valued fields are CBOR BYTE STRINGS, not arrays of integers:");
    println!("  prev_hash   -> 5820 <32 bytes>   (version 2 emitted 9820 <32 ints>)");
    println!("  scripts     -> 0x40|len prefixed byte strings");
    println!("That encoding is most of version 3's ~3x size reduction over version 2.");
}
