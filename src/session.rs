use std::fs;
use std::io::Write;

use datetime::{LocalDateTime, ISO};
use read_input::prelude::*;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};

use crate::{passwords, share_passwords, users, utils};
use crate::passwords::{EncryptedPassword, UnencryptedPassword};


pub struct Session {
    name: String,
    login_time: LocalDateTime,
    passwords_key: Vec<u8>,
    user_file: users::UserFiles,
    private_key: RsaPrivateKey,
    passwords: Vec<EncryptedPassword>,
    nest_modified: bool,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedData {
    pub private_key: RsaPrivateKey,
    pub passwords: Vec<EncryptedPassword>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    nonce: Vec<u8>,
    data: Vec<u8>,
}


impl Session {
    fn new(name: &str, master_key: Vec<u8>, passwords_key: Vec<u8>) -> Self {
        let user_file = users::get_user_files(name);
        let encrypted = get_encrypted(&user_file.nest).expect("Could not read encrypted data");
        let decrypted = crypto::data_decrypt(&master_key, &encrypted.nonce, &encrypted.data)
            .expect("Could not decrypt data");

        Session {
            name: String::from(name),
            login_time: LocalDateTime::now(),
            nest_modified: false,
            passwords_key,
            user_file,
            private_key: decrypted.private_key,
            passwords: decrypted.passwords,
        }
    }

    pub fn try_login(user: &str, password: &str) -> Result<Self, String> {
        // check user exists
        if !users::user_exists(user) {
            return Err(String::from("User doesn't exist"));
        }

        let master_key = crypto::derive_master_key(password)?;
        if !crypto::verify_master_key(&master_key, &users::get_user_nest_path(user)) {
            return Err(String::from("Wrong master key"));
        }

        // passwords key is a key derived from the master password concatenated with a constant
        let passwords_key = crypto::derive_passwords_key(password)?;

        Ok(Session::new(&user, master_key, passwords_key))
    }

    pub fn home(mut self) {
        match self.retrieve_shared_passwords() {
            Ok(true) => {
                println!("Imported successfully.");
            }
            Err(s) => println!("Failed to import passwords : {}", s),
            _ => (), // No shared password
        }

        loop {
            println!("Connected since {}", self.login_time.iso());

            if self.nest_modified {
                println!("[!] The database was modified. It will be saved at logout or manually with `write`\n\n")
            }

            println!(
                "\n\
            --- Menu ---\n\n\
                get    : Get passwords\n\
                add    : Add a password\n\
                remove : Remove a password\n\
                share  : Share a password with another user\n\n\
                change : Change your master password\n\
                write  : Apply changes of the nest file\n\n\
                exit   : Log out  and exit\n\n"
            );

            match input::<String>()
                .msg("What do you want to do ? ")
                .get()
                .as_str()
            {
                "g" | "get" => self.get_passwords_handler(),
                "a" | "add" => self.add_password_handler(),
                "r" | "remove" => self.remove_password_handler(),
                "s" | "share" => self.share_password_handler(),
                "w" | "write" => {
                    self.write_change_handler();
                }
                "c" | "change" => {
                    if self.change_master_password_handler() {
                        self.logout(false); // changes have already been written
                        return;
                    };
                }
                "e" | "exit" => break,
                _ => (),
            }

            utils::cls(None);
        }

        self.logout(true);
    }

    fn add_password_handler(&mut self) {
        utils::cls(Some("--- Add a new password ---"));
        let label: String = input().msg("Label: ").get();
        let username: String = input().msg("Username (optional): ").get();
        let password: String = input().msg("Password: ").get();

        let unencrypted = UnencryptedPassword {
            label,
            username,
            password,
        };

        let password = match unencrypted.encrypt(&self.passwords_key) {
            Ok(encrypted) => encrypted,
            Err(_) => {
                utils::msg_continue("Could not add password to the database...");
                return;
            }
        };

        match self.add_password(password) {
            Ok(true) => utils::msg_continue("Password added to the database"),
            _ => utils::msg_continue("Couldn't add the password :/"),
        }
    }

    fn add_password(&mut self, password: EncryptedPassword) -> Result<bool, String> {
        // check if the lab + password combination exist
        if let Some(i) =
        passwords::password_label_exists(&self.passwords, &password.label, &password.username)
        {
            println!("This label/username combination already exists.");
            if !utils::ask_continue("Do you want to update the password ?", false) {
                return Ok(false);
            }
            self.passwords.remove(i);
        }

        self.passwords.push(password);
        self.nest_modified = true;
        Ok(true)
    }

    fn change_master_password_handler(&mut self) -> bool {
        utils::cls(Some("--- Master password changing ---"));

        // verify current password
        let old_master_password =
            rpassword::prompt_password("Please enter your current master password: ").unwrap();

        if crypto::verify_master_password(&old_master_password, &self.user_file.nest) {
            // input new password
            let new_master_password = users::input_password_twice();
            let new_master_key = crypto::derive_master_key(&new_master_password).unwrap();
            let new_passwords_key = crypto::derive_passwords_key(&new_master_password).unwrap();

            // re-encrypt passwords
            let mut new_passwords: Vec<EncryptedPassword> = Vec::new();

            for p in &self.passwords {
                let reencrypted = match p.reencrypt(&self.passwords_key, &new_passwords_key) {
                    Ok(p) => p,
                    Err(e) => {
                        utils::msg_continue(&format!(
                            "Couldn't re-encrypt passwords. Nothing changed. {}",
                            e.to_string()
                        ));
                        return false;
                    }
                };
                new_passwords.push(reencrypted);
            }

            // apply changes
            self.passwords = new_passwords;

            if write_nest(
                &self.name,
                &new_master_key,
                self.private_key.clone(),
                self.passwords.clone(),
            )
                .is_err()
            {
                utils::msg_continue("Could not write in the nest file :/");
                return false;
            }

            self.nest_modified = true;
            utils::msg_continue("Master password updated successfully !");
            return true;
        }

        utils::msg_continue("Wrong master password");
        false
    }

    fn get_passwords_handler(&self) {
        utils::cls(Some("--- Your passwords ---"));

        // Input password to get
        if let Some(i) = passwords::select_password(&self.passwords) {
            // Decrypt and show password
            let encrypted = self.passwords.get(i).unwrap();
            match encrypted.decrypt(&self.passwords_key) {
                Ok(decrypted) => {
                    print!("Password with label '{}' ", decrypted.label);
                    if !decrypted.username.is_empty() {
                        print!("and username '{}' ", decrypted.username)
                    }
                    println!("is :    {}", decrypted.password);
                    utils::msg_continue("");
                }
                Err(e) => utils::msg_continue(&format!(
                    "Couldn't decrypt the password. {}",
                    e.to_string()
                )),
            }
        }
    }

    fn logout(mut self, write_changes: bool) {
        if self.nest_modified && write_changes {
            // ask for password
            if utils::ask_continue("Your nest file has changed. Do you want to save it ?", true)
                && !self.write_change_handler()
            {
                return;
            }
        }

        utils::msg_continue("Logged out.");
    }

    fn remove_password_handler(&mut self) {
        if let Some(i) = passwords::select_password(&self.passwords) {
            if utils::ask_continue("Are you sure you want to do that ?", false) {
                self.passwords.remove(i);
                self.nest_modified = true;
                println!("Password removed !");

                utils::msg_continue("Password removed !");
                return;
            }
        }

        utils::msg_continue("No change has been made.");
    }

    fn retrieve_shared_passwords(&mut self) -> Result<bool, String> {
        let shared_passwords = share_passwords::get_shared_passwords(&self.user_file.shared)?;

        if shared_passwords.is_empty() {
            return Ok(false);
        }

        // ask for confirmation before importing
        utils::cls(Some(&format!(
            " You have {} shared passwords waiting to be imported. ",
            shared_passwords.len()
        )));
        if utils::ask_continue("Do you want to import them ?", true) {
            for shared in &shared_passwords {
                if let Ok(password) = share_passwords::reencrypt_shared_password(
                    &self.private_key,
                    &self.passwords_key,
                    shared,
                ) {
                    self.passwords.push(password);
                }
            }
        }

        // the failed imports will not be kept
        share_passwords::create_shared_file(&self.name)?;

        Ok(!shared_passwords.is_empty())
    }

    fn share_password_handler(&self) {
        utils::cls(Some("--- Password sharing ---"));

        // input username
        let username: String = input()
            .msg("Who do you want to share the password to ? ")
            .get();
        if !users::user_exists(&username) {
            utils::cls(Some("This user does not exist."));
            return;
        }

        if !self.passwords.is_empty() {
            // select a password to share
            println!("Your passwords:");
            passwords::password_list(&self.passwords);

            // Input password to get
            let i = input::<usize>()
                .repeat_msg(format!(
                    "Which password do you want to share ? (0-{}) ",
                    self.passwords.len() - 1
                ))
                .min_max(0, self.passwords.len() - 1)
                .get();
            let password = self.passwords.get(i).unwrap();

            // Value verification
            print!(
                "Selected user: {}\nSelected password: {} with username '{}'",
                username, password.label, password.username
            );

            // Confirmation
            if utils::ask_continue("\nDo you want to continue ?", true) {
                match share_passwords::share_password(
                    &self.name,
                    &self.passwords_key,
                    &self.private_key,
                    &username,
                    password.clone(),
                ) {
                    Ok(_) => utils::msg_continue("Password shared successfully."),
                    Err(s) => utils::msg_continue(
                        format!("Error while sharing password : {}", s).as_str(),
                    ),
                }
            }
        } else {
            utils::msg_continue("You have no password in your nest.");
        }
    }

    fn write_change_handler(&mut self) -> bool {
        if self.nest_modified {
            // ask for password
            let mut master_password: String = rpassword::prompt_password(
                "Please enter your master password or keep empty to cancel : ",
            )
                .unwrap();
            while !crypto::verify_master_password(&master_password, &self.user_file.nest) {
                if master_password.is_empty() {
                    return false;
                }

                master_password =
                    rpassword::prompt_password("Wrong master key, try again: ").unwrap();
            }

            let master_key = crypto::derive_master_key(&master_password).unwrap();
            if let Err(e) = write_nest(
                &self.name,
                &master_key,
                self.private_key.clone(),
                self.passwords.clone(),
            ) {
                println!("Could not write in the nest file :/ {}", e);
            } else {
                utils::msg_continue("Nest saved successfully !");
                self.nest_modified = false;
            }
        }
        return true;
    }
}

pub fn get_encrypted(filename: &str) -> Result<EncryptedData, String> {
    let data = utils::read_file(filename);
    utils::deserialize::<EncryptedData>(data)
}

pub fn write_nest(
    name: &str,
    key: &Vec<u8>,
    private_key: RsaPrivateKey,
    passwords: Vec<EncryptedPassword>,
) -> Result<bool, String> {
    let nest = users::get_user_nest_path(name);

    // encrypt data
    let decrypted_data = DecryptedData {
        private_key,
        passwords,
    };
    let encrypted_data = crypto::data_encrypt(key, decrypted_data)?;

    let encrypted_data = utils::serialize::<EncryptedData>(&encrypted_data)?;

    // write the file
    match fs::File::create(&nest) {
        Ok(mut f) => match f.write_all(encrypted_data.as_slice()) {
            Ok(_) => Ok(true),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}


pub mod crypto {
    use crate::utils::config::PBKDF_SALT;
    use aead::{Aead, NewAead};
    use chacha20poly1305::ChaCha20Poly1305;
    use pbkdf2::password_hash::{PasswordHasher, SaltString};
    use pbkdf2::Pbkdf2;
    use rand_core::{OsRng, RngCore};

    use super::*;

    pub fn verify_master_password(master_password: &str, file: &str) -> bool {
        let master_key = derive_master_key(master_password).unwrap();
        verify_master_key(&master_key, file)
    }

    pub fn verify_master_key(master_key: &Vec<u8>, file: &str) -> bool {
        let encrypted = get_encrypted(file).unwrap();
        data_decrypt(master_key, &encrypted.nonce, &encrypted.data).is_ok()
    }

    pub fn derive_passwords_key(master_password: &str) -> Result<Vec<u8>, String> {
        //ref: https://docs.rs/pbkdf2/latest/pbkdf2/
        let concat_string = "-.R_NEST0";
        let password = format!("{master_password}{concat_string}");

        match Pbkdf2.hash_password(password.as_bytes(), &SaltString::new(PBKDF_SALT).unwrap()) {
            Ok(h) => Ok(h.hash.unwrap().as_bytes().to_vec()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn derive_master_key(master: &str) -> Result<Vec<u8>, String> {
        //ref: https://docs.rs/pbkdf2/latest/pbkdf2/
        let password = master.as_bytes();

        match Pbkdf2.hash_password(password, &SaltString::new(PBKDF_SALT).unwrap()) {
            Ok(h) => Ok(h.hash.unwrap().as_bytes().to_vec()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn data_decrypt(
        key: &Vec<u8>,
        nonce: &Vec<u8>,
        buffer: &[u8],
    ) -> Result<DecryptedData, String> {
        let key_bytes = chacha20poly1305::Key::from_slice(key.as_slice());
        let cipher = ChaCha20Poly1305::new(key_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce.as_slice());

        match cipher.decrypt(nonce, buffer) {
            Ok(d) => utils::deserialize::<DecryptedData>(d),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn data_encrypt(
        key: &Vec<u8>,
        decrypted_data: DecryptedData,
    ) -> Result<EncryptedData, String> {
        let buffer = utils::serialize::<DecryptedData>(&decrypted_data)?;

        let key_bytes = chacha20poly1305::Key::from_slice(key.as_slice());
        let cipher = ChaCha20Poly1305::new(key_bytes);

        let mut random: [u8; 12] = [0; 12];
        OsRng.fill_bytes(&mut random);
        let nonce = chacha20poly1305::Nonce::from_slice(&random);

        match cipher.encrypt(nonce, buffer.as_slice()) {
            Ok(data) => Ok(EncryptedData {
                data,
                nonce: nonce.to_vec(),
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}