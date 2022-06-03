mod passwords;
mod session;
mod share_passwords;
mod users;
mod utils;


use read_input::prelude::*;


fn main() {
    utils::cls(Some("Welcome to Ernest :D"));
    println!("Pro Tip: You can navigate faster in the menus by entering the first letter of a command.\n\n");

    loop {
        println!(
            "--- Ernest --- \n\n\
            login : Log in\n\
            add   : Add a new user\n\
            exit  : Exit\n\n"
        );

        match input::<String>()
            .msg("What do you want to do ? ")
            .get()
            .as_str()
        {
            "l" | "login" => login_handler(),
            "a" | "add" => useradd_handler(),
            "e" | "exit" => {
                println!("Have a nice day !");
                break;
            }
            _ => {}
        }
    }
}

fn useradd_handler() {
    // Get user name
    let username: String = input().msg("Name of the new user: ").get();

    if users::user_exists(&username) {
        utils::cls(Some("This user already exists."));
        return;
    }

    // Get password
    let password = users::input_password_twice();

    println!("\nCreating your user ...");
    match users::create_user(&username, &password) {
        Ok(t) => utils::msg_continue(&format!("User added ! ({})", t.directory)),
        Err(e) => utils::msg_continue(&format!("An error occurred... :/ {}", e.to_string())),
    }
}

fn login_handler() {
    utils::cls(Some("--- Login ---\n"));

    let user: String = input().msg("Username: ").get();
    let password = rpassword::prompt_password("Password: ").unwrap();

    // get password, repeat
    match session::Session::try_login(&user, &password) {
        Ok(res) => {
            utils::cls(Some(&format!("Successfully logged-in as {}", user)));
            res.home();
        }
        Err(_) => {
            utils::msg_continue("Could not login, the user or the password does not exist.");
            return;
        }
    }
}