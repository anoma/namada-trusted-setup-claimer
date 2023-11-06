use anyhow::{anyhow, Context};
use bip39::{Language, Mnemonic};
use clap::Parser;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use rpassword::prompt_password;
use zeroize::Zeroizing;

const PROMPT: &str = "reading mnemonic phrase from stdin:\n";

/// Sign arbitrary messages with Namada trusted setup keys
#[derive(Clone, Parser, Debug)]
enum Operation {
    /// Sign the provided message
    Sign {
        /// Mnemonic to derive the key used to participate
        /// in Namada's trusted setup cerimony
        #[arg(long)]
        mnemonic: Option<Zeroizing<String>>,
    },
    /// Verify a signature over the provided message
    Verify {
        /// Hex encoded public key
        #[arg(short = 'k', long)]
        public_key: String,
        /// Hex signature over the provided message
        #[arg(short, long)]
        signature: String,
    },
}

/// Sign arbitrary messages with Namada trusted setup keys
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    /// UTF-8 string data to sign
    #[arg(short, long)]
    message: String,
    /// Operation to perform (signing or verification)
    #[command(subcommand)]
    operation: Operation,
}

fn main() -> anyhow::Result<()> {
    let Arguments { message, operation } = Arguments::parse();

    match operation {
        Operation::Sign { mnemonic } => sign(message, mnemonic),
        Operation::Verify {
            public_key,
            signature,
        } => verify(message, public_key, signature),
    }
}

fn verify(message: String, public_key: String, signature: String) -> anyhow::Result<()> {
    let public_key_bytes = hex::decode(public_key).context("failed to hex decode public key")?;
    let signature_bytes = hex::decode(signature).context("failed to hex decode signature")?;

    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|err| anyhow!("invalid public key bytes: {err}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| anyhow!("invalid signature bytes: {err}"))?;

    public_key
        .verify(message, &signature)
        .map_err(|err| anyhow!("invalid signature: {err}"))?;

    Ok(())
}

fn sign(message: String, mnemonic: Option<Zeroizing<String>>) -> anyhow::Result<()> {
    let keypair = get_keypair_from(mnemonic)?;
    let signature = keypair.sk.sign(message, Some(Default::default()));

    println!("public key : {}", hex::encode(*keypair.pk));
    println!("signature  : {}", hex::encode(*signature));

    Ok(())
}

fn get_keypair_from(mnemonic: Option<Zeroizing<String>>) -> anyhow::Result<KeyPair> {
    let mnemonic = mnemonic
        .map_or_else(
            || {
                prompt_password(PROMPT)
                    .map(Zeroizing::new)
                    .map_err(|err| anyhow!("failed to read mnemonic: {err}"))
            },
            Ok,
        )?
        // remove any extra spaces from the mnemonic seed phrase
        .split_whitespace()
        .fold(Zeroizing::new(String::new()), |mut acc, word| {
            acc.push_str(word);
            acc.push(' ');
            acc
        });
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic)
        .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
    let seed = {
        let seed_64 = mnemonic.to_seed_normalized("");
        let mut seed_32 = [0; 32];
        seed_32.copy_from_slice(&seed_64[..32]);
        Seed::new(seed_32)
    };
    Ok(KeyPair::from_seed(seed))
}
