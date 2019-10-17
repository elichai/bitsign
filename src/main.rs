mod cli;
mod hkdf;

use bitcoin::secp256k1::constants::SECRET_KEY_SIZE;
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::util::address::Payload;
use bitcoin::util::key::PublicKey as BitcoinPublicKey;
use bitcoin::util::misc;
use bitcoin::{Address, PrivateKey};
use cli::Options;
use getrandom::getrandom;
use hkdf::{HKDFExpand, HKDFExtract};
use serde_json::{self, json, Value};
use std::io::BufRead;
use std::{error, fmt, io, process, sync::atomic};
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};
use structopt::StructOpt;

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
        match e {
            Error::Clap(e) => e.exit(),
            Error::VerificationFailed => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
    }
}

#[derive(Debug)]
enum Error {
    Clap(ClapError),
    VerificationFailed,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Clap(e) => e.fmt(f),
            Error::VerificationFailed => write!(f, "Failed Verifying the signature"),
        }
    }
}

impl From<ClapError> for Error {
    fn from(error: ClapError) -> Self {
        Error::Clap(error)
    }
}

fn handle_cli(opt: Options) -> Result<(), Error> {
    match opt {
        Options::Generate { net, uncompressed, address_type, json } => {
            let secp = Secp256k1::signing_only();

            let mut entropy = vec![0u8; 32];
            getrandom(&mut entropy).unwrap();

            entropy.reserve(128);
            if !json {
                println!("Input your own randomness by hitting keys randomly and then hit 'enter' when you're done: (This will be on top of random entropy from the OS)");
                io::stdin().lock().read_until(b'\n', &mut entropy).unwrap();
            }
            let hkdf = HKDFExtract::extract(&[], &entropy);
            let key = generate_key(hkdf);

            let mut privkey = PrivateKey { compressed: !uncompressed, network: net, key };
            let pubkey = privkey.public_key(&secp);
            let address = match address_type {
                AddressType::P2pkh => Address::p2pkh(&pubkey, net),
                AddressType::P2Wpkh => Address::p2wpkh(&pubkey, net),
                AddressType::P2shwpkh => Address::p2shwpkh(&pubkey, net),
            };
            let mut address_str = address.to_string();
            let mut privkey_str = privkey.to_wif();
            let mut value = Value::Null;
            if json {
                value = json!({
                "address": address_str,
                "privkey": privkey_str
                });
                println!("{}", serde_json::to_string_pretty(&value).unwrap()); // Shouldn't fail as it's already a Value.
            } else {
                println!("\nBitcoin Address: {}", address.to_string());
                println!("WIF private key: {}", privkey.to_wif());
            }

            // Cleanup
            atomic::compiler_fence(atomic::Ordering::SeqCst);
            unsafe {
                cleanup! {entropy.as_mut_ptr(), entropy.len()}
                cleanup! {address_str.as_mut_ptr(), address_str.len()}
                cleanup! {privkey_str.as_mut_ptr(), privkey_str.len()}
                cleanup! {privkey.key.as_mut_ptr(), SECRET_KEY_SIZE}
                if let Some(obj) = value.as_object_mut() {
                    if let Some(Value::String(s)) = obj.get_mut("privkey") {
                        cleanup! {s.as_mut_ptr(), s.len()}
                    }
                }
            }
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }

        Options::Sign { mut privkey, message, json } => {
            let secp = Secp256k1::signing_only();

            let hash = misc::signed_msg_hash(&message);
            let msg = Message::from_slice(&hash[..]).unwrap(); // Can never panic because it's the right size.
            let (id, sig) = secp.sign_recoverable(&msg, &privkey.key).serialize_compact();
            //vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
            let mut rec_sig = [0u8; 65];
            rec_sig[1..].copy_from_slice(&sig);
            rec_sig[0] = if privkey.compressed { 27 + id.to_i32() as u8 + 4 } else { 27 + id.to_i32() as u8 };
            let sig = base64::encode(&rec_sig[..]);
            if json {
                let value = json!({
                "signature": sig,
                });
                println!("{}", serde_json::to_string_pretty(&value).unwrap()); // Shouldn't fail as it's already a Value.
            } else {
                println!("Message Signed. Signature: {}", sig);
            }

            // Cleanup
            atomic::compiler_fence(atomic::Ordering::SeqCst);
            unsafe {
                cleanup! {privkey.key.as_mut_ptr(), SECRET_KEY_SIZE}
            }
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }

        Options::Verify { address, message, signature, json } => {
            let secp = Secp256k1::verification_only();

            let invalid_sig = || ClapError::with_description("Invalid Signature", ClapErrorKind::ValueValidation);
            let sig = base64::decode(&signature)
                .map_err(|_| ClapError::with_description("The signature isn't a valid base64", ClapErrorKind::ValueValidation))?;
            if sig.len() != 65 {
                return Err(invalid_sig().into());
            }
            let recid = RecoveryId::from_i32(i32::from((sig[0] - 27) & 3)).map_err(|_| invalid_sig())?;
            let recsig = RecoverableSignature::from_compact(&sig[1..], recid).map_err(|_| invalid_sig())?;
            let hash = misc::signed_msg_hash(&message);
            let msg = Message::from_slice(&hash[..]).unwrap(); // Can never panic because it's the right size.

            let pubkey = BitcoinPublicKey {
                key: secp.recover(&msg, &recsig).map_err(|_| invalid_sig())?,
                compressed: ((sig[0] - 27) & 4) != 0,
            };

            let (restore, core_supported) = match address.payload {
                Payload::PubkeyHash(_) => (Address::p2pkh(&pubkey, address.network), true),
                Payload::WitnessProgram { .. } => (Address::p2wpkh(&pubkey, address.network), false),
                Payload::ScriptHash(_) => (Address::p2shwpkh(&pubkey, address.network), false),
            };
            if json {
                let value = json!({
                "verified": address == restore,
                "core_supported": core_supported,
                });
                println!("{}", serde_json::to_string_pretty(&value).unwrap()); // Shouldn't fail as it's already a Value.
            } else if address == restore {
                if core_supported {
                    println!("Signature Verified!");
                } else {
                    println!(
                        "Signature Verified!. Warning: This isn't a P2PKH so Bitcoin Core doesn't support verifying this signature"
                    )
                }
            } else {
                return Err(Error::VerificationFailed);
            }
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

#[cfg(test)]
mod tests {
    use crate::cli::Options;
    use crate::{handle_cli, AddressType, Error};
    use bitcoin::{Network, PrivateKey};
    use std::mem;

    const MSG: &str = "Testing this thing";

    #[test]
    fn test_generate() {
        let opt = Options::Generate { net: Network::Bitcoin, uncompressed: false, address_type: AddressType::P2shwpkh };
        handle_cli(opt).unwrap();
    }

    #[test]
    fn test_sign() {
        let opt = Options::Sign {
            privkey: PrivateKey::from_wif("KyD7YaaoguEgSCKPWVtudxUx9cfx4Sv9X4uxtpt3nVuB8jqkHxfH").unwrap(),
            message: MSG.to_string(),
        };
        handle_cli(opt).unwrap();
    }

    #[test]
    fn test_verify() {
        let opt = Options::Verify {
            address: "1HtJJJRNLWyTBB9xNYa2tN9Gsfjbji9wdy".parse().unwrap(), // "KysPSSWeoimuCpq8eTFNBPTYCXkeCCzDEZPKjkMoHu6SBCGBW9yQ".
            message: MSG.to_string(),
            signature: "HyMkfamQtiO8pf1kKcC8+Q20Ami3/Yn4H0h6/FEzfybAYyUbpHRdcTvvz8u9DwIRfHzeZDbol7dzM1sUjzR3yLk=".to_string(),
        };
        handle_cli(opt).unwrap();
    }

    #[test]
    fn test_verify_fail() {
        let mut msg = MSG.to_string();
        msg.push('1');
        let opt = Options::Verify {
            address: "1HtJJJRNLWyTBB9xNYa2tN9Gsfjbji9wdy".parse().unwrap(), // "KysPSSWeoimuCpq8eTFNBPTYCXkeCCzDEZPKjkMoHu6SBCGBW9yQ".
            message: msg,
            signature: "HyMkfamQtiO8pf1kKcC8+Q20Ami3/Yn4H0h6/FEzfybAYyUbpHRdcTvvz8u9DwIRfHzeZDbol7dzM1sUjzR3yLk=".to_string(),
        };
        let err = handle_cli(opt).unwrap_err();
        assert_eq!(mem::discriminant(&err), mem::discriminant(&Error::VerificationFailed));
    }
}
