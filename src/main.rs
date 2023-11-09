//use anyhow::{anyhow, Context as AnyhowContext};
use anyhow::anyhow;
use bip39::{Language, Mnemonic};
use ed25519_compact::{KeyPair, Seed};
use zeroize::Zeroizing;

mod consts {
    pub const MNEMONIC_PROMPT: &str =
        "Please enter the seed phrase that you used during the Namada Trusted Setup ceremony in November 2022.";

    pub const MENU_PROMPT: &str = "What would you like to do?";

    pub const SIGN_PROMPT: &str = "Please enter the challenge from the website:";

    pub const OPTION_SHOW_PUBKEY: &str = "Show Pubkey";
    pub const OPTION_SIGN_MSG: &str = "Sign Message";
    pub const OPTION_QUIT: &str = "Quit";
}

struct Context {
    keypair: KeyPair,
}

fn main() -> anyhow::Result<()> {
    let context = {
        let seed_phrase = inquire::Password::new(consts::MNEMONIC_PROMPT)
            .with_display_mode(inquire::PasswordDisplayMode::Full)
            .without_confirmation();

        let mnemonic_phrase = seed_phrase.prompt().map(Zeroizing::new)?;
        Context::new(&mnemonic_phrase)?
    };

    println!();
    loop {
        let option_prompt = inquire::Select::new(
            consts::MENU_PROMPT,
            vec![
                consts::OPTION_SHOW_PUBKEY,
                consts::OPTION_SIGN_MSG,
                consts::OPTION_QUIT,
            ],
        );
        let selection = option_prompt.prompt();
        match selection {
            Ok(consts::OPTION_SHOW_PUBKEY) => context.show_pubkey()?,
            Ok(consts::OPTION_SIGN_MSG) => context.sign_message()?,
            Ok(consts::OPTION_QUIT) => return Ok(()),
            _ => unreachable!(),
        }
        println!();
    }
}

impl Context {
    fn new(mnemonic_input: &str) -> anyhow::Result<Self> {
        // remove any extra spaces from the mnemonic seed phrase
        let mnemonic = mnemonic_input.split_whitespace().fold(
            Zeroizing::new(String::new()),
            |mut acc, word| {
                acc.push_str(word);
                acc.push(' ');
                acc
            },
        );
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic)
            .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
        let seed = {
            let seed_64 = mnemonic.to_seed_normalized("");
            let mut seed_32 = [0; 32];
            seed_32.copy_from_slice(&seed_64[..32]);
            Seed::new(seed_32)
        };
        let keypair = KeyPair::from_seed(seed);
        Ok(Self { keypair })
    }

    fn show_pubkey(&self) -> anyhow::Result<()> {
        println!("Public Key: {}", hex::encode(*self.keypair.pk));
        Ok(())
    }

    fn sign_message(&self) -> anyhow::Result<()> {
        let msg = inquire::Text::new(consts::SIGN_PROMPT);
        println!();

        let msg_prompt = msg.prompt();
        let signature = self.keypair.sk.sign(msg_prompt?, Some(Default::default()));

        println!("Signature: {}", hex::encode(*signature));
        Ok(())
    }
}
