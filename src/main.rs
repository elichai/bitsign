mod cli;
mod hkdf;

use cli::Options;
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};
use structopt::StructOpt;

fn main() {
    let opt = Options::from_args();
    if let Err(e) = handle_cli(opt) {
        e.exit();
    }
}

fn handle_cli(opt: Options) -> Result<(), ClapError> {
    match opt {
        Options::GenerateKeys { net } => {
            dbg!(net);
        }
    };

    Ok(())
}
