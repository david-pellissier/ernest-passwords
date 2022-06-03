use std::{fs, io};
use std::fs::File;
use std::io::{stdin, BufRead, Read, Write};

use read_input::prelude::*;
use rmp_serde;
use serde::{Deserialize, Serialize};


pub fn append_line_to_file(mut data: String, filename: &str) -> Result<(), String> {
    data.push('\n'); // add new line
    append_to_file(data.as_bytes(), filename)
}

pub fn append_to_file(data: &[u8], filename: &str) -> Result<(), String> {
    // source: https://mockstacks.com/How-to-append-to-a-file-in-Rust
    match fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(filename)
    {
        Ok(mut f) => {
            f.write_all(data).unwrap();
            Ok(())
        }
        Err(_) => Err("Couldn't append to the file".to_string()),
    }
}

pub fn ask_continue(msg: &str, default: bool) -> bool {
    let options = if default { "[Y/n]" } else { "[N/y]" };
    let input: String = input().msg(&format!("{} {}", msg, options)).get();
    match input.as_str() {
        "y" | "Y" => true,
        "n" | "N" => false,
        _ => default,
    }
}

pub fn cls(msg: Option<&str>) {
    // source: https://stackoverflow.com/questions/34837011/how-to-clear-the-terminal-screen-in-rust-after-a-new-line-is-printed
    print!("{}[2J", 27 as char);
    if msg.is_some() {
        println!("{}", msg.unwrap());
    }
    println!()
}

pub fn deserialize<T: for<'a> Deserialize<'a>>(data: Vec<u8>) -> Result<T, String> {
    match rmp_serde::decode::from_slice(data.as_slice()) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.to_string()),
    }
}

pub fn msg_continue(msg: &str) {
    println!("{}", msg);
    wait_key_press();
    cls(None);
}

pub fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
}

pub fn read_lines(filename: &str) -> io::Result<io::Lines<io::BufReader<File>>> {
    // Source: https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/read_lines.html
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn serialize<T: Serialize>(object: &T) -> Result<Vec<u8>, String> {
    match rmp_serde::encode::to_vec(object) {
        Ok(u) => Ok(u),
        Err(e) => return Err(e.to_string()),
    }
}

pub fn wait_key_press() {
    println!("\nPress any key to continue...");
    stdin().read_line(&mut "".to_string()).unwrap(); // 0-length buffer
}


pub mod config {
    // DO NOT CHANGE THIS after having created a user
    pub const PBKDF_SALT: &str = "isntthatpepper";
    // simple regex for testing purpose. Please note that only the master password is checked with this regex.
    pub const PWD_REGEX: &str = r"^.{8,64}$";
    pub const USERS_PATH: &str = "./users";
}
