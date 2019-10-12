# bitsign
[![Build Status](https://travis-ci.org/elichai/bitsign.svg?branch=master)](https://travis-ci.org/elichai/bitsign)
[![Latest version](https://img.shields.io/crates/v/bitsign.svg)](https://crates.io/crates/bitsign)
![License](https://img.shields.io/crates/l/bitsign.svg)
[![dependency status](https://deps.rs/repo/github/elichai/bitsign/status.svg)](https://deps.rs/repo/github/elichai/bitsign)

A tool to generate bitcoin keys, sign and verify messages using bitcoin keys. (compatible with Bitcoin Core)


## Installation

### From Sources
With Rust's package manager cargo, you can install bitsign via:

```sh
cargo install --force bitsign
```

# Usage

Generating keys: 
`bitsign generate`

The tool will draw randomness from the OS, but for the paranoid users it also lets you input your own entropy by hitting random keys at stdin.

Optionally you can pass `--type` for p2pkh/p2wpkh/p2shwpkh [default: p2wpkh]. <br>
and `--net` for bitcoin/regtest/testnet [default: bitcoin]. <br>
or even `--uncompressed`(If for some reason you really need uncompressed keys).

Sign a message: 
`bitsign sign <privkey> <message>` 

Verify a message:
`bitsign verify <address> <message> <signature>`

This tool will also try and verify messages with p2kpkh and p2shwpkh but bear in mind that Bitcoin Core won't accept that same verification (a warning will get printed).

# Example
```sh
$ bitsign generate --type p2pkh
Input your own randomness by hitting keys randomly and then hit 'enter' when you're done: (This will be on top of random entropy from the OS)
fsdfkldsfkdsjflwkjfkwe

Bitcoin Address: 1AupUZ3sAdTjZSdG4D52eFoHdPtjwGZrTj
WIF private key: KwQoPt6dL91fxRBWdt4nkCVrfo4ipeLcaD4ZCLntoTPhKGNgGqGm

$ bitsign sign  KwQoPt6dL91fxRBWdt4nkCVrfo4ipeLcaD4ZCLntoTPhKGNgGqGm "This is an example"
Message Signed. Signature: IFbPlcOleYublXob8/6w3i1crI89TW9s0wOvZCge+E26MwW4v7zxOEF8KWf5ko9l9SLGq8jVbcNzW45vw8Zlwes=

$ bitsign verify 1AupUZ3sAdTjZSdG4D52eFoHdPtjwGZrTj "This is an example" IFbPlcOleYublXob8/6w3i1crI89TW9s0wOvZCge+E26MwW4v7zxOEF8KWf5ko9l9SLGq8jVbcNzW45vw8Zlwes=
Signature Verified!
```

```sh
$ bitsign generate
Input your own randomness by hitting keys randomly and then hit 'enter' when you're done: (This will be on top of random entropy from the OS)
dfgheriednfgjeriekodmnfkhuroiewokdm

Bitcoin Address: bc1q64mh4n7u9xxvfdsml3pasr4tsn85dewnsfexuf
WIF private key: KxUeV889U8Zxfzf2qCSVFBTkZZQMVXodUJDutT7pBf4XdjcEds7p

$ bitsign sign KxUeV889U8Zxfzf2qCSVFBTkZZQMVXodUJDutT7pBf4XdjcEds7p "Example with bech32 segwit"
Message Signed. Signature: IAAr1NgFG6htGNqrzBFn2dod9o+chvIaEz14UayiD0UILig1HVqLgAsz5DNzh8Yw4SBixhkHkeMpGUFt1xy/o7Q=

$ bitsign verify bc1q64mh4n7u9xxvfdsml3pasr4tsn85dewnsfexuf "Example with bech32 segwit" IAAr1NgFG6htGNqrzBFn2dod9o+chvIaEz14UayiD0UILig1HVqLgAsz5DNzh8Yw4SBixhkHkeMpGUFt1xy/o7Q=
Signature Verified!. Warning: This isn't a P2PKH so Bitcoin Core doesn't support verifying this signature

```
