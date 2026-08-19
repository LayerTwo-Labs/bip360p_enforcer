//! Dev helper for manually testing BIP360+ OP_CAT enforcement on regtest.
//!
//! OP_CAT (byte 0xfe) is enforced by the validator inside Taproot v1 script-path
//! leaves — there is no wallet RPC for it, so this tool hand-builds the pieces:
//!
//!   cargo run --example opcat_dev -- address
//!       Print the regtest Taproot v1 address committing to the demo OP_CAT leaf
//!       (`OP_CAT OP_SHA256 <sha256("abcd")> OP_EQUAL`). Fund this address.
//!
//!   cargo run --example opcat_dev -- spend \
//!       --txid <funding_txid> --vout <n> --value <sat> --to <regtest_addr> [--invalid]
//!       Print the raw hex of a script-path spend of that funding output. The
//!       witness reveals the leaf and supplies the two CAT pieces ("ab","cd").
//!       With --invalid, the pieces are wrong ("ax","cd") so the leaf evaluates
//!       false and the enforcer must invalidate the block. Mine it with:
//!         bitcoin-cli -regtest generateblock <miner_addr> '["<hex>"]'
//!
//! The demo leaf has NO signature, so the spend needs no key and no prevout —
//! exactly the fail-closed path the Phase-4 interpreter enforces.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "dev CLI helper whose purpose is to print address / tx hex to the terminal"
)]

use std::str::FromStr as _;

use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
    consensus::encode::serialize_hex,
    hashes::{Hash as _, sha256},
    opcodes::all::{OP_EQUAL, OP_SHA256},
    script::Builder,
    secp256k1::{Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
};

const OP_CAT: u8 = 0xfe;
const FEE_SATS: u64 = 1_000;
/// Fixed internal key so the address is deterministic across runs.
const INTERNAL_KEY_BYTES: [u8; 32] = [0x11; 32];

fn demo_leaf() -> ScriptBuf {
    let expected = sha256::Hash::hash(b"abcd").to_byte_array();
    Builder::new()
        .push_opcode(bitcoin::Opcode::from(OP_CAT))
        .push_opcode(OP_SHA256)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(expected.as_slice()).unwrap())
        .push_opcode(OP_EQUAL)
        .into_script()
}

fn spend_info() -> (bitcoin::taproot::TaprootSpendInfo, ScriptBuf) {
    let secp = Secp256k1::new();
    let internal = SecretKey::from_slice(&INTERNAL_KEY_BYTES)
        .unwrap()
        .keypair(&secp);
    let (internal_xonly, _) = internal.x_only_public_key();
    let leaf = demo_leaf();
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal_xonly)
        .unwrap();
    (info, leaf)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let secp = Secp256k1::new();

    match cmd {
        Some("address") => {
            let (info, leaf) = spend_info();
            let addr = Address::p2tr_tweaked(info.output_key(), Network::Regtest);
            println!("address: {addr}");
            println!("leaf_hex: {}", hex::encode(leaf.as_bytes()));
            let control = info
                .control_block(&(leaf, LeafVersion::TapScript))
                .expect("control block");
            println!("control_hex: {}", hex::encode(control.serialize()));
        }
        Some("spend") => {
            let txid = Txid::from_str(&arg(&args, "--txid").expect("--txid")).expect("txid");
            let vout: u32 = arg(&args, "--vout").expect("--vout").parse().expect("vout");
            let value: u64 = arg(&args, "--value")
                .expect("--value")
                .parse()
                .expect("value");
            let to = arg(&args, "--to").expect("--to");
            let invalid = args.iter().any(|a| a == "--invalid");

            let to_spk = Address::from_str(&to)
                .expect("address")
                .require_network(Network::Regtest)
                .expect("regtest address")
                .script_pubkey();

            let (info, leaf) = spend_info();
            let control = info
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .expect("control block");

            // Two CAT pieces: "ab"+"cd" = "abcd" (valid) or "ax"+"cd" (invalid).
            let (p1, p2): (&[u8], &[u8]) = if invalid {
                (b"ax", b"cd")
            } else {
                (b"ab", b"cd")
            };
            let mut witness = Witness::new();
            witness.push(p1);
            witness.push(p2);
            witness.push(leaf.as_bytes());
            witness.push(control.serialize());

            let tx = Transaction {
                version: Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint { txid, vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(value.saturating_sub(FEE_SATS)),
                    script_pubkey: to_spk,
                }],
            };
            let _ = &secp;
            println!("{}", serialize_hex(&tx));
        }
        _ => {
            eprintln!(
                "usage:\n  opcat_dev address\n  opcat_dev spend --txid <txid> --vout <n> \
                 --value <sat> --to <regtest_addr> [--invalid]"
            );
            std::process::exit(2);
        }
    }
}
