use crate::AddressType;
use bitcoin::{Address, Network, PrivateKey};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Bitsign", about = "A tool for Generating Bitcoin Keys, signing and verifying.")]
pub enum Options {
    /// Generate a pair of keys.
    Generate {
        // TODO: Rename Bitcoin to Mainnet.
        // TODO: Make lowercase.
        /// Choose the desired netwrok: bitcoin/regtest/testnet
        #[structopt(default_value = "bitcoin", parse(try_from_str), long = "net")]
        net: Network,
        /// Produce uncompressed keys (not recommended)
        #[structopt(long)]
        uncompressed: bool,
        ///Choose an address type p2pkh/p2wpkh/p2shwpkh
        #[structopt(name = "type", default_value = "p2wpkh", parse(try_from_str = parse_address_type), long = "type")]
        address_type: AddressType,
        /// Return the results as json
        #[structopt(long)]
        json: bool,
    },
    /// Sign a message using your bitcoin address.
    Sign {
        /// A WIF private key.
        #[structopt(parse(try_from_str = PrivateKey::from_wif))]
        privkey: PrivateKey,
        /// The message to sign on.
        message: String,
        /// Return the results as json
        #[structopt(long)]
        json: bool,
    },
    /// Verify a message signed by a bitcoin address.
    Verify {
        /// The bitcoin address
        #[structopt(parse(try_from_str))]
        address: Address,
        /// The message being verified.
        message: String,
        /// The Base64 Signature.
        signature: String,
        /// Return the results as json
        #[structopt(long)]
        json: bool,
    },
}

fn parse_address_type(src: &str) -> Result<AddressType, &'static str> {
    let src = src.to_ascii_lowercase();
    match src.as_str() {
        "p2pkh" => Ok(AddressType::P2pkh),
        "p2wpkh" => Ok(AddressType::P2Wpkh),
        "p2shwpkh" => Ok(AddressType::P2shwpkh),
        _ => Err(""),
    }
}
