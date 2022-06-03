use std::ops::Index;

use read_input::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::utils;


#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedPassword {
    pub label: String,
    pub username: String,
    nonce: Vec<u8>,
    encrypted: Vec<u8>,
}

impl EncryptedPassword {
    pub fn decrypt(&self, password_key: &Vec<u8>) -> Result<UnencryptedPassword, String> {
        let password = crypto::decrypt(
            password_key,
            self.nonce.as_slice(),
            self.encrypted.as_slice(),
        )?;

        Ok(UnencryptedPassword {
            label: String::from(&self.label),
            username: String::from(&self.username),
            password,
        })
    }

    pub fn reencrypt(&self, old_key: &Vec<u8>, new_key: &Vec<u8>) -> Result<Self, String> {
        self.decrypt(old_key)?.encrypt(new_key)
    }

    pub fn new(
        password_key: &Vec<u8>,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, String> {
        crypto::password_encrypt(password_key, label, username, password)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnencryptedPassword {
    pub label: String,
    pub username: String,
    pub password: String,
}

impl UnencryptedPassword {
    pub fn encrypt(self, passwords_key: &Vec<u8>) -> Result<EncryptedPassword, String> {
        EncryptedPassword::new(passwords_key, &self.label, &self.username, &self.password)
    }
}


pub fn password_label_exists(
    passwords: &Vec<EncryptedPassword>,
    label: &str,
    username: &str,
) -> Option<usize> {
    for i in 0..passwords.len() {
        let p = passwords.index(i);
        if p.label == label && &p.username == username {
            return Some(i);
        }
    }

    None
}

pub fn password_list(passwords: &Vec<EncryptedPassword>) {
    println!("N°, Label || Username\n------------------------------");
    for i in 0..passwords.len() {
        let p = passwords.index(i);
        println!(
            "{} : {} || {}",
            i,
            p.label,
            if p.username.is_empty() {
                "--"
            } else {
                &p.username
            }
        )
    }
    println!()
}

pub fn select_password(passwords: &Vec<EncryptedPassword>) -> Option<usize> {
    if !passwords.is_empty() {
        password_list(&passwords);

        // Input password to get
        let i = input::<usize>()
            .msg(format!(
                "Select a password (>={} to cancel) : ",
                passwords.len()
            ))
            .get();
        if i < passwords.len() {
            return Some(i);
        }
    } else {
        utils::msg_continue("You have no password in your nest.");
    }

    None
}

pub fn validate_password(password: &String) -> bool {
    let regex = Regex::new(utils::config::PWD_REGEX).unwrap();
    regex.is_match(password)
}


mod crypto {
    use crate::passwords::EncryptedPassword;
    use aead::{Aead, NewAead};
    use aes_gcm::Aes256Gcm;
    use rand_core::{OsRng, RngCore};

    pub fn decrypt(password_key: &Vec<u8>, nonce: &[u8], data: &[u8]) -> Result<String, String> {
        let key = aes_gcm::Key::from_slice(password_key);
        let cipher = Aes256Gcm::new(&key);

        match cipher.decrypt(&aes_gcm::Nonce::from_slice(nonce), data) {
            Ok(t) => Ok(String::from_utf8(t).unwrap()),
            Err(e) => Err(e.to_string()),
        }
    }

    // Note: cannot be "encrypt" function returning generic data, because the nonce has to be returned with the encrypted data -> we need a struct anyway
    pub fn password_encrypt(
        password_key: &Vec<u8>,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<EncryptedPassword, String> {
        let key = aes_gcm::Key::from_slice(password_key.as_slice());
        let cipher = Aes256Gcm::new(key);
        let mut random: [u8; 12] = [0; 12];
        OsRng.fill_bytes(&mut random);
        let nonce = chacha20poly1305::Nonce::from_slice(&random);

        match cipher.encrypt(
            &aes_gcm::Nonce::from_slice(nonce.as_slice()),
            password.as_bytes(),
        ) {
            Ok(t) => Ok(EncryptedPassword {
                label: String::from(label),
                username: String::from(username),
                nonce: nonce.to_vec(),
                encrypted: t,
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}