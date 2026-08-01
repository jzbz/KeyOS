// SPDX-FileCopyrightText: 2026 The Decred developers
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Decred Wallet entry point. Mirrors gui-app-bitcoin/src/main.rs structure:
// pull in the security API, declare the app via the `app!` macro, build a
// StoredValue<AppState>, and wire each feature module's init().
//
// Scope (deliberately small): receive addresses, view accounts, and SIGN an
// unsigned-tx package that Cake Wallet built. No SPV, no broadcast, no staking,
// no mixing. Transport for signing is QR (animated UR) or SD card.

#![feature(must_not_suspend)]
#![deny(must_not_suspend)]

use slint_keyos_platform::{
    app,
    gui_server_api::{navigation::qrscanner::MatchedQrResult, InputMessage},
    StoredValue,
};

mod account_store;
mod balance;
mod create_account;
mod keys;
mod passphrase;
mod receive;
mod sign_tx;
mod state;

use state::AppState;

// Brings `crate::Security` + the GetSeed/GetDeviceId message-allowed wiring
// into scope, exactly as the Bitcoin app does.
security::use_api!();

app!("Decred Wallet");
fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    cx.config.enable_swipe_back.set(false);

    let state = StoredValue::new(AppState::new(ui.as_weak()));

    // Feature wiring. Each module installs its Slint callbacks against `state`.
    balance::init(state);
    receive::init(state);
    sign_tx::init(state);
    create_account::init(state);
    passphrase::init(state);

    // Universal-scan handoff (same pattern as the Bitcoin app): the OS
    // scanner already captured and reassembled the QR and routed it here via
    // the manifest's qrMatchRules — consume the pending payload rather than
    // making the user scan the same code twice.
    cx.set_input_handler({
        let gui_api = cx.gui.clone();
        move |input| {
            if input.msg == InputMessage::NavigationFocused {
                let Ok(Some(nav_bytes)) = gui_api.navigate_pending() else {
                    log::error!("Navigation focused but no pending nav request");
                    return;
                };
                if let Some(matched) = MatchedQrResult::from_slice(&nav_bytes) {
                    let MatchedQrResult { scan_result, .. } = matched;
                    sign_tx::reset_for_incoming_scan(state);
                    if let Err(e) = sign_tx::handle_scan_result(state, scan_result) {
                        log::error!("universal scan failed: {e:?}");
                        sign_tx::show_scan_error(state, &e.to_string());
                    }
                }
            }
        }
    });

    ui.run().expect("UI running");
}
