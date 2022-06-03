use std::fs;
use std::io::Write;

use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::{passwords, session, share_passwords, utils};
use crate::utils::{deserialize, serialize};


#[derive(Serialize, Deserialize)]
pub struct PublicProfile {
    pub name: String,
    pub public_key: RsaPublicKey,
    signature: Vec<u8>,
}

pub struct UserFiles {
    pub directory: String,
    pub profile: String,
    pub nest: String,
    pub shared: String,
}

pub fn create_user(user: &str, master_password: &str) -> Result<UserFiles, String> {
    let user_paths = get_user_files(user);

    // generate key pair
    let key_pair = crypto::generate_key_pair()?;
    let private_key = key_pair.0;
    let public_key = key_pair.1;

    let master_key = session::crypto::derive_master_key(master_password)?;
    let public_key_bin = utils::serialize::<RsaPublicKey>(&public_key)?;
    let signature = share_passwords::crypto::asym_sign_priv(&private_key, public_key_bin.as_slice())?;

    // create user profile
    let user_profile = PublicProfile {
        name: String::from(user),
        public_key,
        signature,
    };
    let user_profile_serialized = serialize::<PublicProfile>(&user_profile)?;
    deserialize::<PublicProfile>(user_profile_serialized.clone()).unwrap();

    // create files
    // ideally, we should set correct permissions

    if let Err(e) = fs::create_dir(&user_paths.directory) {
        return Err(e.to_string());
    }

    // write profile
    match fs::File::create(&user_paths.profile) {
        Ok(mut f) => {
            if f.write_all(user_profile_serialized.as_slice()).is_err() {
                return Err(String::from("Could not write file"));
            }
        }
        Err(e) => return Err(e.to_string()),
    }

    // create and write nest
    session::write_nest(user, &master_key, private_key, Vec::new())?;

    // create shared file
    share_passwords::create_shared_file(user)?;

    Ok(user_paths)
}

pub fn get_user_directory(user: &str) -> String {
    format!("{}/{}", utils::config::USERS_PATH, user)
}

pub fn get_user_files(user: &str) -> UserFiles {
    let directory = get_user_directory(user);
    let profile = get_user_profile_path(user);
    let nest = get_user_nest_path(user);
    let shared_folder = get_user_shared_path(user);

    UserFiles {
        directory,
        profile,
        nest,
        shared: shared_folder,
    }
}

pub fn get_user_profile_path(user: &str) -> String {
    format!("{}/profile", get_user_directory(user))
}

pub fn get_user_nest_path(user: &str) -> String {
    format!("{}/{}.nest", get_user_directory(user), user)
}

pub fn get_user_shared_path(user: &str) -> String {
    format!("{}/shared.nest", get_user_directory(user))
}

pub fn user_exists(user: &str) -> bool {
    let user_files = get_user_files(user);
    let check_values = [&user_files.nest, &user_files.profile, &user_files.shared];

    for s in check_values {
        if !std::path::Path::new(s).exists() {
            return false;
        }
    }
    true
}

pub fn input_password_twice() -> String {
    let password: String;
    loop {
        let pass1 = rpassword::prompt_password("Enter your password: ").unwrap();
        let pass2 = rpassword::prompt_password("Confirm your password: ").unwrap();

        if pass1 != pass2 {
            println!("These two passwords don't match. Please try again.")
        } else if !passwords::validate_password(&pass1) {
            println!("This password does not match the password policy (defined in utils.rs)")
        } else {
            // correct value
            password = pass1;
            break;
        }
    }

    password
}


mod crypto {
    use rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    pub fn generate_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey), String> {
        let private = match RsaPrivateKey::new(&mut OsRng, 2048) {
            Ok(t) => t,
            Err(e) => return Err(e.to_string()),
        };
        let public = RsaPublicKey::from(&private);

        Ok((private, public))
    }
}
