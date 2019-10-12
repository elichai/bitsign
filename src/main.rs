mod cli;
mod hkdf;

use bitcoin::secp256k1::constants::SECRET_KEY_SIZE;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, PrivateKey};
use cli::Options;
use getrandom::getrandom;
use hkdf::{HKDFExpand, HKDFExtract};
use std::io::BufRead;
use std::{io, sync::atomic};
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};
use structopt::StructOpt;
use bitcoin::util::misc;
use secp256k1::Message;

const INFO: &[u8] = b"bitsign";

macro_rules! cleanup {
    ($ptr_exp:expr, $size:expr) => {
        let ptr = $ptr_exp;
        for i in 0..$size {
            ptr.add(i).write_volatile(0);
        }
    };
}

#[derive(Debug)]
pub enum AddressType {
    P2pkh,
    P2Wpkh,
    P2shwpkh,
}

fn main() {
    let opt = Options::from_args();
    if let Err(e) = handle_cli(opt) {
        e.exit();
    }
}

fn handle_cli(opt: Options) -> Result<(), ClapError> {
    let secp = Secp256k1::signing_only();
    match opt {
        Options::Generate { net, uncompressed, address_type } => {
            let mut entropy = vec![0u8; 32];
            getrandom(&mut entropy).unwrap();

            entropy.reserve(128);
            println!("Input your own randomness by hitting keys randomly and then hit 'enter' when you're done: (This will be on top of random entropy from the OS)");
            io::stdin().lock().read_until(b'\n', &mut entropy).unwrap();
            let hkdf = HKDFExtract::extract(&[], &entropy);
            let key = generate_key(hkdf);

            let mut privkey = PrivateKey { compressed: !uncompressed, network: net, key };
            let pubkey = privkey.public_key(&secp);
            let address = match address_type {
                AddressType::P2pkh => Address::p2pkh(&pubkey, net),
                AddressType::P2Wpkh => Address::p2wpkh(&pubkey, net),
                AddressType::P2shwpkh => Address::p2shwpkh(&pubkey, net),
            };
            println!("\nBitcoin Address: {}", address.to_string());
            println!("WIF private key: {}", privkey.to_wif());

            // Cleanup
            atomic::compiler_fence(atomic::Ordering::SeqCst);
            unsafe {
                cleanup! {entropy.as_mut_ptr(), entropy.len()}
                cleanup! {privkey.key.as_mut_ptr(), SECRET_KEY_SIZE}
            }
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        },
        Options::Sign { mut privkey, message } => {
            let hash = misc::signed_msg_hash(&message);
            let msg = Message::from_slice(&hash[..]).unwrap(); // Can never panic because it's the right size.
            let (id, sig) = secp.sign_recoverable(&msg, &privkey.key).serialize_compact();
            //vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
            let mut rec_sig = [0u8; 65];
            rec_sig[1..].copy_from_slice(&sig);
            rec_sig[0] = if privkey.compressed {
                27 + id.to_i32() as u8 + 4
            } else {
                27 + id.to_i32() as u8
            };
            let sig = base64::encode(&rec_sig[..]);
            println!("Signed Message: {}", sig);

            // Cleanup
            atomic::compiler_fence(atomic::Ordering::SeqCst);
            unsafe {
                cleanup! {privkey.key.as_mut_ptr(), SECRET_KEY_SIZE}
            }
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }
    };

    Ok(())
}

fn generate_key(mut source: HKDFExpand) -> SecretKey {
    let mut key = vec![0u8; 32];
    source.expand(INFO, &mut key);
    loop {
        if let Ok(k) = SecretKey::from_slice(&key) {
            return k;
        } else {
            source.expand(INFO, &mut key);
        }
    }
}
