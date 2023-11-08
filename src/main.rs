use anyhow::{anyhow, Context};
use bip39::{Language, Mnemonic};
use clap::Parser;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use rpassword::prompt_password;
use zeroize::Zeroizing;
use inquire;

const PROMPT: &str = "reading mnemonic phrase from stdin:\n";

fn main() {

    // TODO: Implement seed phrase validation
    let sp_validator = | _input: &str | Ok(inquire::validator::Validation::Valid);

    let seed_phrase = inquire::Password::new("Please enter the seed phrase that you used during the Namada Trusted Setup ceremony in November 2022.")
        .with_display_mode(inquire::PasswordDisplayMode::Full)
        .with_validator(sp_validator);

    println!("");

    let sp_prompt = seed_phrase.prompt();

    let state = match sp_prompt {
        Ok(sp) => {
            // TODO: Handle the error gracefully
            let kp = mnemonic_to_key(&sp).unwrap();
            State{keypair: kp}
        },
        Err(_) => {
            // TODO: Handle the error gracefully
            panic!("couldn't parse the seed phrase");
        }
    };

    let option_prompt = inquire::Select::new("What would you like to do?", vec!["Show Pubkey", "Sign Message"]);
    let selection = option_prompt.prompt();
    match selection {
        Ok("Show Pubkey") => show_pubkey(&state),
        // ask for an extra prompt with the message and then sign
        Ok("Sign Message") => sign_message(&state),
        // handle the error
        _ => panic!("invalid"),
    }
}


pub struct State {
    keypair: KeyPair,
}

fn mnemonic_to_key(sp: &String) -> anyhow::Result<KeyPair> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, sp)
        .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
    let seed = {
        let seed_64 = mnemonic.to_seed_normalized("");
        let mut seed_32 = [0; 32];
        seed_32.copy_from_slice(&seed_64[..32]);
        Seed::new(seed_32)
    };
    Ok(KeyPair::from_seed(seed))
}

fn sign_message(state: &State) {
    let msg = inquire::Text::new("Please enter the challenge from the website:");
    println!("");
    let msg_prompt = msg.prompt();
    let signature = state.keypair.sk.sign(msg_prompt.unwrap(), Some(Default::default()));

    println!("Signature  : {}", hex::encode(*signature));
}

fn show_pubkey(state: &State) {
    println!("Public Key : {}", hex::encode(*state.keypair.pk));
}


// /// Sign arbitrary messages with Namada trusted setup keys
// #[derive(Clone, Parser, Debug)]
// enum Operation {
//     /// Sign the provided message
//     Sign {
//         /// Mnemonic to derive the key used to participate
//         /// in Namada's trusted setup cerimony
//         #[arg(long)]
//         mnemonic: Option<Zeroizing<String>>,
//     },
//     /// Verify a signature over the provided message
//     Verify {
//         /// Hex encoded public key
//         #[arg(short = 'k', long)]
//         public_key: String,
//         /// Hex signature over the provided message
//         #[arg(short, long)]
//         signature: String,
//     },
// }

// /// Sign arbitrary messages with Namada trusted setup keys
// #[derive(Clone, Parser, Debug)]
// #[command(version, about, long_about = None)]
// struct Arguments {
//     /// UTF-8 string data to sign
//     #[arg(short, long)]
//     message: String,
//     /// Operation to perform (signing or verification)
//     #[command(subcommand)]
//     operation: Operation,
// }



// fn verify(message: String, public_key: String, signature: String) -> anyhow::Result<()> {
//     let public_key_bytes = hex::decode(public_key).context("failed to hex decode public key")?;
//     let signature_bytes = hex::decode(signature).context("failed to hex decode signature")?;

//     let public_key = PublicKey::from_slice(&public_key_bytes)
//         .map_err(|err| anyhow!("invalid public key bytes: {err}"))?;
//     let signature = Signature::from_slice(&signature_bytes)
//         .map_err(|err| anyhow!("invalid signature bytes: {err}"))?;

//     public_key
//         .verify(message, &signature)
//         .map_err(|err| anyhow!("invalid signature: {err}"))?;

//     Ok(())
// }

// fn sign(message: String, mnemonic: Option<Zeroizing<String>>) -> anyhow::Result<()> {
//     let keypair = get_keypair_from(mnemonic)?;
//     let signature = keypair.sk.sign(message, Some(Default::default()));

//     println!("public key : {}", hex::encode(*keypair.pk));
//     println!("signature  : {}", hex::encode(*signature));

//     Ok(())
// }

// fn get_keypair_from(mnemonic: Option<Zeroizing<String>>) -> anyhow::Result<KeyPair> {
//     let mnemonic = mnemonic
//         .map_or_else(
//             || {
//                 prompt_password(PROMPT)
//                     .map(Zeroizing::new)
//                     .map_err(|err| anyhow!("failed to read mnemonic: {err}"))
//             },
//             Ok,
//         )?
//         // remove any extra spaces from the mnemonic seed phrase
//         .split_whitespace()
//         .fold(Zeroizing::new(String::new()), |mut acc, word| {
//             acc.push_str(word);
//             acc.push(' ');
//             acc
//         });
//     let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic)
//         .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
//     let seed = {
//         let seed_64 = mnemonic.to_seed_normalized("");
//         let mut seed_32 = [0; 32];
//         seed_32.copy_from_slice(&seed_64[..32]);
//         Seed::new(seed_32)
//     };
//     Ok(KeyPair::from_seed(seed))
// }
