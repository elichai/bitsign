use bitcoin::Network;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Lorenz",
    about = "A tool for encrypting/decrypting a file for multiple participants."
)]
pub enum Options {
    /// Generate Pairs of keys.
    #[structopt(name = "generate-keys")]
    GenerateKeys {
        // TODO: Rename Bitcoin to Mainnet.
        // TODO: Make lowercase.
        /// Choose the correct magic bytes(test/reg/main net)
        #[structopt(default_value = "bitcoin", parse(try_from_str))]
        net: Network,
    },
}
