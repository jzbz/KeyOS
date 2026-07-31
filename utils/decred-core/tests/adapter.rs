// SPDX-License-Identifier: Apache-2.0
//! Adapter smoke test: proves the `decred_core::…` paths KeyOS apps compile
//! against still reach the real dcr-rs implementation, end to end — build a
//! format version 3 package, validate it (which now also verifies each input's
//! funding transaction and proves change ownership), run the trustless review
//! from an account xpub, sign it, and verify the produced signature against a
//! recomputed sighash. The exhaustive consensus vectors (dcrd KATs, BIP32
//! chains, a real mainnet tx) live upstream in dcr-rs and run in its CI;
//! duplicating them here would only let the copies drift.
//!
//! The version 1 packages this file used to pin are gone: dcr-rs refuses
//! versions 1 and 2 outright, deliberately, because the sender picks the
//! version and accepting an old one reopens the amount-understatement attack
//! that version 2 closed.

use decred_core::address::p2pkh_script;
use decred_core::airgap::{
    decode_sign_request, encode_sign_request, sign_request, InputMeta, OutputMeta, SignRequest,
    FORMAT_VERSION,
};
use decred_core::hashing::hash160;
use decred_core::hd::{ExtPrivKey, BRANCH_EXTERNAL};
use decred_core::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use decred_core::sighash::signature_hash_all;
use decred_core::tx::{MsgTx, TxOut};
use decred_core::Network;

const ENTROPY_HEX: &str = "348360ae0a69b1883b0dfc060136108dfcabe9f4bf8af3e866b742fb53f1caa5";

/// Build a funding transaction paying `value` to `script` at vout 0, and return
/// its txid with its prefix serialization. Format version 3 requires this per
/// input: the device recomputes blake256 over the prefix, requires it to equal
/// prev_hash, and requires the referenced output to carry exactly the declared
/// amount and script — which is what makes `value_in` verified evidence rather
/// than a companion assertion.
fn funding_for(script: &[u8], value: i64) -> ([u8; 32], Vec<u8>) {
    let tx = MsgTx {
        version: 1,
        tx_in: Vec::new(),
        tx_out: vec![TxOut { value, version: 0, pk_script: script.to_vec() }],
        lock_time: 0,
        expiry: 0,
    };
    (tx.tx_hash(), tx.serialize_prefix())
}

/// The exact CBOR layout of a version 3 package, cross-checked against dcr-rs.
///
/// These are the bytes upstream pins in `tests/airgap_review.rs`
/// (`cbor_layout_pins_v3_encoding`), whose doc comment asks for exactly this:
/// the version 1 form of that test compared against KeyOS-produced bytes and so
/// was a genuine interop check, and versions 2 and 3 lost it because no KeyOS
/// encoder spoke either. Regenerating them here from `decred_core` restores the
/// cross-implementation check — if the two crates ever disagree about the wire
/// format, this fails.
///
/// The byte-string headers are the point of version 3: `5820` (bytes(32)) for
/// prev_hash where version 2 emitted `9820` (array(32) of one-or-two-byte
/// ints), which is most of the ~3x size reduction.
#[test]
fn v3_wire_layout_matches_dcr_rs_golden() {
    const GOLDEN_HEX: &str = "87030100001a00067932818958200707070707070707070707070707\
                              07070707070707070707070707070707070701001affffffff1a075b\
                              cd1500054676a914aa88ac44deadbeef81861a05f5e100004676a914\
                              bb88acf50107";
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 424_242,
        inputs: vec![InputMeta {
            prev_hash: [7u8; 32],
            prev_index: 1,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 123_456_789,
            branch: 0,
            index: 5,
            prev_script: vec![0x76, 0xa9, 0x14, 0xaa, 0x88, 0xac],
            // Layout fixture, not a valid package: `encode_sign_request` does
            // no validation, so this placeholder never has to hash to
            // prev_hash. Semantic checks live in the end-to-end test below.
            prev_tx_prefix: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        }],
        outputs: vec![OutputMeta {
            value: 100_000_000,
            version: 0,
            pk_script: vec![0x76, 0xa9, 0x14, 0xbb, 0x88, 0xac],
            is_change: true,
            branch: Some(1),
            index: Some(7),
        }],
        account_fp: None,
    };
    let golden: String = GOLDEN_HEX.split_whitespace().collect();
    assert_eq!(hex::encode(encode_sign_request(&req).unwrap()), golden, "v3 wire layout drifted from dcr-rs");

    // The byte-string encoding itself, asserted directly: a revert to #[n(..)]
    // (or to #[b(..)], which looks right and changes nothing on an owned type)
    // would still round-trip and still pass every other assertion here.
    assert!(golden.contains("5820"), "prev_hash must be a CBOR byte string");
    assert!(!golden.contains("9820"), "prev_hash must not be an array of ints");

    let back = decode_sign_request(&hex::decode(&golden).unwrap()).unwrap();
    assert_eq!(back.expiry, 424_242);
    assert_eq!(back.inputs[0].index, 5);
    assert_eq!(back.inputs[0].prev_tx_prefix.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    assert!(back.outputs[0].is_change);
    assert_eq!(back.outputs[0].branch, Some(1));
    assert_eq!(back.outputs[0].index, Some(7));
}

/// Superseded format versions must be refused, not tolerated: the sender
/// chooses the version, so accepting one would let a hostile companion opt out
/// of the verification versions 2 and 3 added.
#[test]
fn superseded_format_versions_are_refused() {
    let script = p2pkh_script(&[0x11u8; 20]).to_vec();
    let (prev_hash, prefix) = funding_for(&script, 100_000);
    let mut req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash,
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 100_000,
            branch: BRANCH_EXTERNAL,
            index: 0,
            prev_script: script,
            prev_tx_prefix: Some(prefix),
        }],
        outputs: vec![OutputMeta {
            value: 94_000,
            version: 0,
            pk_script: p2pkh_script(&[0x22u8; 20]).to_vec(),
            is_change: false,
            branch: None,
            index: None,
        }],
        account_fp: None,
    };

    for stale in [1u8, 2u8] {
        req.format_version = stale;
        let bytes = encode_sign_request(&req).unwrap();
        assert!(decode_sign_request(&bytes).is_err(), "format version {stale} must be refused, not accepted");
    }
}

#[test]
fn review_sign_and_verify_end_to_end() {
    let secp = Secp256k1::new();
    let entropy = hex::decode(ENTROPY_HEX).unwrap();
    let master = ExtPrivKey::from_entropy(&entropy, "", Network::Mainnet).unwrap();
    let account = master.account_key(&secp, 0).unwrap();

    // Spend this wallet's own external/0 key, with change back to external/1.
    let key0 = account.address_key(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let pk0 = key0.compressed_pubkey(&secp);
    let script0 = p2pkh_script(&hash160(&pk0)).to_vec();

    let key1 = account.address_key(&secp, BRANCH_EXTERNAL, 1).unwrap();
    let change_script = p2pkh_script(&hash160(&key1.compressed_pubkey(&secp))).to_vec();

    let (prev_hash, prev_tx_prefix) = funding_for(&script0, 100_000);

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash,
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 100_000,
            branch: BRANCH_EXTERNAL,
            index: 0,
            prev_script: script0.clone(),
            prev_tx_prefix: Some(prev_tx_prefix),
        }],
        outputs: vec![
            OutputMeta {
                value: 60_000,
                version: 0,
                pk_script: p2pkh_script(&[0x42u8; 20]).to_vec(),
                is_change: false,
                branch: None,
                index: None,
            },
            OutputMeta {
                value: 34_000,
                version: 0,
                pk_script: change_script,
                is_change: true,
                branch: Some(BRANCH_EXTERNAL),
                index: Some(1),
            },
        ],
        account_fp: None,
    };

    // Round-trip through the wire, as the device does — nothing is reviewed
    // from an in-memory struct on the real path.
    let req = decode_sign_request(&encode_sign_request(&req).unwrap()).unwrap();
    req.validate().unwrap();

    // Trustless review from the neutered account key: no private material.
    let xpub = account.neuter(&secp);
    req.check_owned_inputs(&secp, &xpub).unwrap();
    let summary = req.review_owned(&secp, &xpub).unwrap();
    assert_eq!(summary.fee, summary.input_total - summary.output_total);
    assert_eq!(summary.fee, 6_000);
    // The device classifies these itself rather than trusting is_change: the
    // foreign output is a recipient, ours is proven change.
    assert_eq!(summary.recipients.len(), 1);
    assert_eq!(summary.recipients[0].1, 60_000);
    assert_eq!(summary.change.len(), 1);
    assert_eq!(summary.change[0].1, 34_000);

    // Sign, reparse, and verify the first signature against our own sighash.
    let signed = sign_request(&secp, &master, &req).unwrap();
    let tx = MsgTx::parse_full(&signed).unwrap();
    let ss = &tx.tx_in[0].signature_script;
    let l1 = ss[0] as usize;
    assert_eq!(ss[l1], 0x01, "SigHashAll");
    let der = &ss[1..l1];
    let pubkey = &ss[2 + l1..2 + l1 + ss[1 + l1] as usize];
    assert_eq!(pubkey, &pk0[..], "signed with the re-derived key");

    let sighash = signature_hash_all(&tx, 0, &script0).unwrap();
    let sig = Signature::from_der(der).unwrap();
    let pk = PublicKey::from_slice(pubkey).unwrap();
    secp.verify_ecdsa(&Message::from_digest(sighash), &sig, &pk).expect("adapter-path signature verifies");
}

/// A companion that lies about an input's amount is caught by the funding
/// transaction, which is the whole point of format version 2 onwards: Decred's
/// signature hash does not commit to input amounts, so before this the fee on
/// the review screen was an unverifiable assertion and a mempool that rewrites
/// ValueIn from the utxo set paid the difference to the miner.
#[test]
fn understated_input_amount_is_refused() {
    let script = p2pkh_script(&[0x11u8; 20]).to_vec();
    let (prev_hash, prev_tx_prefix) = funding_for(&script, 100_000);

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash,
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            // The funding output really carries 100_000; claim less, so the
            // reviewer would be shown a small fee and the miner paid the rest.
            value_in: 70_000,
            branch: BRANCH_EXTERNAL,
            index: 0,
            prev_script: script,
            prev_tx_prefix: Some(prev_tx_prefix),
        }],
        outputs: vec![OutputMeta {
            value: 64_000,
            version: 0,
            pk_script: p2pkh_script(&[0x22u8; 20]).to_vec(),
            is_change: false,
            branch: None,
            index: None,
        }],
        account_fp: None,
    };

    assert!(req.validate().is_err(), "an understated value_in must be refused");
}
