//! Print the `rc4-hmac` ciphertext of a known input, so that a second implementation can be asked to
//! read it back.
//!
//! `scripts/heimdal-rc4-vectors.sh` drives this: Heimdal encrypts, this prints, Heimdal decrypts, and
//! only if the last step returns the plaintext is a fixture written. The example exists because that
//! check needs a program that produces ciphertext on demand; nothing else in the crate wants one.
//!
//! Usage: `cargo run --example rc4_vector -- <key-hex> <usage> <plaintext-hex> <confounder-hex>`

use rrl_crypto::{Cipher, Enctype, Key, OwnCipher};

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "{text:?} is not whole octets");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        eprintln!("usage: rc4_vector <key-hex> <usage> <plaintext-hex> <confounder-hex>");
        std::process::exit(2);
    }
    let key = Key::new(Enctype::Rc4Hmac, unhex(&args[0])).expect("a 16-octet key");
    let usage: u32 = args[1].parse().expect("a usage number");
    let plaintext = unhex(&args[2]);
    let confounder = unhex(&args[3]);

    let ciphertext = OwnCipher
        .encrypt_with_confounder(&key, usage, &plaintext, &confounder)
        .expect("the ciphertext");
    println!(
        "{}",
        ciphertext
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}
