use std::fs;

use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::passwords::{EncryptedPassword, UnencryptedPassword};
use crate::users::{get_user_files, PublicProfile};
use crate::{users, utils};


#[derive(Serialize, Deserialize)]
pub struct SharedPassword {
    pub sender: String,
    pub encrypted: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SharedPassword {
    pub fn new(
        sender: &str,
        password: UnencryptedPassword,
        public_key: &RsaPublicKey,
        private_key: &RsaPrivateKey,
    ) -> Result<Self, String> {
        let data = utils::serialize::<UnencryptedPassword>(&password)?;
        let encrypted = crypto::asym_crypt_pub(&public_key, data.as_slice())?;
        let signature = crypto::asym_sign_priv(&private_key, &encrypted)?;
        Ok(SharedPassword {
            sender: String::from(sender),
            encrypted,
            signature,
        })
    }
}


pub fn create_shared_file(user: &str) -> Result<(), String> {
    if let Err(e) = fs::File::create(&users::get_user_shared_path(user)) {
        return Err(e.to_string());
    }

    Ok(())
}

pub fn get_profile(username: &str) -> Result<PublicProfile, String> {
    let path = users::get_user_profile_path(username);
    let data = utils::read_file(&path);
    utils::deserialize::<PublicProfile>(data)
}

pub fn get_shared_passwords(filename: &str) -> Result<Vec<SharedPassword>, String> {
    // Get passwords
    let lines = utils::read_lines(filename).unwrap();
    let mut shared_passwords: Vec<SharedPassword> = Vec::new();

    // every line of the file is a SharedPassword
    for line in lines {
        if let Ok(s) = line {
            let bytes = base64::decode(&s).unwrap();

            if let Ok(password) = utils::deserialize::<SharedPassword>(bytes.to_vec()) {
                let profile = get_profile(&password.sender)?;
                // verify signature before adding to the shared_password list
                if crypto::asym_verify_pub(
                    &profile.public_key,
                    &password.signature,
                    &password.encrypted,
                ) {
                    shared_passwords.push(password);
                } else {
                    println!("A password sent by {} did not pass the signature verification. It has been ignored.", &profile.name);
                }
            }
        }
    }

    Ok(shared_passwords)
}

pub fn reencrypt_shared_password(
    private_key: &RsaPrivateKey,
    passwords_key: &Vec<u8>,
    shared_password: &SharedPassword,
) -> Result<EncryptedPassword, String> {
    let data = crypto::asym_decrypt_priv(private_key, shared_password.encrypted.as_slice())?;

    match utils::deserialize::<UnencryptedPassword>(data) {
        Ok(unencrypted) => Ok(unencrypted.encrypt(passwords_key)?),
        Err(e) => Err(e.to_string()),
    }
}

pub fn share_password(
    sender: &str,
    sender_passwords_key: &Vec<u8>,
    sender_private_key: &RsaPrivateKey,
    recipient_name: &str,
    password: EncryptedPassword,
) -> Result<(), String> {
    // Retrieve public key
    let user_files = get_user_files(recipient_name);
    let recipient = get_profile(&recipient_name)?;

    // decrypt with symmetric key
    let decrypted = password.decrypt(sender_passwords_key)?;

    // encrypt with recipient's public key
    let shared_password =
        SharedPassword::new(sender, decrypted, &recipient.public_key, sender_private_key)?;
    let shared_data = utils::serialize::<SharedPassword>(&shared_password)?;

    utils::append_line_to_file(base64::encode(shared_data), &user_files.shared)
}


pub mod crypto {
    use rand_core::OsRng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn asym_sign_priv(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, String> {
        let padding = PaddingScheme::new_pss::<sha2::Sha256, OsRng>(OsRng);
        match private_key.sign(padding, sha256_hash(data).as_slice()) {
            Ok(t) => Ok(t),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn asym_verify_pub(public_key: &RsaPublicKey, signature: &[u8], data: &[u8]) -> bool {
        let padding = PaddingScheme::new_pss::<sha2::Sha256, OsRng>(OsRng);
        public_key
            .verify(padding, sha256_hash(data).as_slice(), signature)
            .is_ok()
    }

    pub fn asym_crypt_pub(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
        // Encrypt
        let padding = PaddingScheme::new_oaep::<Sha256>();

        match public_key.encrypt(&mut OsRng, padding, &data[..]) {
            Ok(t) => Ok(t),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn asym_decrypt_priv(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, String> {
        let padding = PaddingScheme::new_oaep::<Sha256>();

        match private_key.decrypt(padding, &data[..]) {
            Ok(t) => Ok(t),
            Err(e) => Err(e.to_string()),
        }
    }
}
