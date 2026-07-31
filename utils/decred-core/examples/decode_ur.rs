// SPDX-License-Identifier: Apache-2.0
//! Decode a captured `UR:DCR-SIGN-REQUEST/...` QR frame back to CBOR bytes and
//! (if it parses) print the SignRequest — the fastest way to inspect what a
//! companion actually put in a QR.
//!
//! ```text
//! cargo run -p decred-core --example decode_ur -- 'UR:DCR-SIGN-REQUEST/...'
//! ```
//!
//! The built-in sample below is a format version 1 capture kept only as a
//! decodable specimen: versions 1 and 2 are refused since dcr-rs 0.3.0, so it
//! reaches bytewords and then reports an unsupported version — which is exactly
//! what an un-updated companion now looks like from the device's side.

use foundation_ur::{bytewords, UR};
fn main() {
    const SAMPLE_V1: &str = "UR:DCR-SIGN-REQUEST/LTADADAEAEAELFLOMKCXCSGLCSIECSLECSCPCSWDCSHHCSMHCSCKCSUOCSSTCSGYCSIACSWDCSLTCSWKCHCSPDCSYLCSCECSPMCSRLCSSSCSWSCSEHCSTACSPRCSFDCSCNCSIMCSDRCSRTCSNEADAECYZMZMZMZMCYAEMKMTLAAEAEMKCFCSKOCSPTBBCSFTCSZSCSWMCSSNCSZCCSLKCSTNCSJPCSVACSLTCSWTCSVECSYLCSDLCSMYBKCSJEBBCSRKCSNECSLOCSPSLOMKCXBDCSZSCSJYCSWLCSNECSDSCSQDCSYACSKECSPKCSJSCSDECSONCSJPCSHYCSTNCSLPCSDYCSHGCSIHCSENCSECCSWFCSVSCSDSCSTBAHCSQZCSLUCSSACSPTATAEAECYZMZMZMZMCYAEAXBTFZAEAEMKCFCSKOCSPTBBCSFTCSZSCSWMCSSNCSZCCSLKCSTNCSJPCSVACSLTCSWTCSVECSYLCSDLCSMYBKCSJEBBCSRKCSNECSLOCSPSLFLRCYAEAOZTVOAEMKCFCSKOCSPTBBCSYLCSLDCSNTCSLNCSIMCSNTCSHYCSEOCSZECSRDCSLUAMCSCXBACSGLCSWMCSPYCSMDCSUOCSJTCSLOCSPSYKLRCYAEMKMTLAAEMKCFCSKOCSPTBBCSSWCSJSCSNBADCSWZBYCSTBCSFMBDBDCSFLCSMECSVACSTECSFXCSSPCSHPCSCKCSJPCSWTCSLOCSPSWKKKPYNSFS";
    let frame = std::env::args().nth(1).unwrap_or_else(|| SAMPLE_V1.to_string());
    let lower = frame.to_lowercase();
    let ur = match UR::parse(&lower) {
        Ok(u) => u,
        Err(e) => {
            println!("parse error: {:?}", e);
            return;
        }
    };
    println!("ur_type: {}", ur.as_type());
    println!("is_single_part: {}", ur.is_single_part());
    let msg = match ur {
        UR::SinglePart { message, .. } => message,
        other => {
            println!("unexpected variant, single={}", other.is_single_part());
            return;
        }
    };
    match bytewords::decode(msg, bytewords::Style::Minimal) {
        Ok(bytes) => {
            println!("DECODED {} bytes, first=0x{:02x}", bytes.len(), bytes[0]);
            println!("hex: {}", hex::encode(&bytes));
            match decred_core::airgap::decode_sign_request(&bytes) {
                Ok(req) => {
                    println!(
                        "\n>>> PARSED AS SignRequest! account={} inputs={} outputs={}",
                        req.account,
                        req.inputs.len(),
                        req.outputs.len()
                    );
                    for (i, o) in req.outputs.iter().enumerate() {
                        println!("  out[{}] value={} is_change={}", i, o.value, o.is_change);
                    }
                }
                Err(e) => println!("\n!!! not a SignRequest (yet): {:?}", e),
            }
        }
        Err(e) => println!("bytewords decode error: {:?}", e),
    }
}
