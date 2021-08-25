extern crate crypto;
extern crate regex;
extern crate reqwest;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use regex::Regex;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // first, pull the most current config

    let client = reqwest::Client::builder()
        .build()?;

    let res = client
        .get("http://127.0.0.1:10000/hosts/home-pc")
        .send()
        .await?;

    let wg_config = res
        .text()
        .await?;

    // hash that config, which should already have a dummy privkey

    let mut hasher = Sha256::new();
    hasher.input_str(&wg_config);
    let hex = hasher.result_str();

    println!("Network Config SHA256 = {}", hex);

    // now, start looking at the config on the disk... first, see if it exists

    let disk_file = "./wg-test.conf";
    let mut current = Path::new(&disk_file).exists();

    let private_key = "MY_PRIVKEY";

    // if it doesn't exist, then it's obviously not current
    // if it does exist, it's considered current (for now)

    if current {
      // so, read the file
      let contents = fs::read_to_string(&disk_file)
          .expect("Something went wrong reading the file");

      // file on the disk is going to have a real privkey, so yeet that for hashing
      let mut regstr = "PrivateKey\\s*=\\s*".to_owned();
      regstr.push_str(&private_key);
      regstr.push_str("\n");

      let re = Regex::new(&regstr).unwrap();
      let transformed = re.replace_all(&contents, "PrivateKey = {{ PRIVATE_KEY }}\n");

      // hash the redacted disk config
      hasher = Sha256::new();
      hasher.input_str(&transformed);
      let newhex = hasher.result_str();
      println!("Current Config SHA256 = {}", newhex);

      // ultimately, disk file is current iff the hashes match
      current = hex == newhex;
    }

    if !current {
      // if we're updating the file, put the real key back
      // (put that thing back where it came from, or so help me!)
      // (it's a work in progress)
      let mut replacement = "PrivateKey = ".to_owned();
      replacement.push_str(&private_key);
      replacement.push_str("\n");

      let re = Regex::new("PrivateKey\\s*=.*\n").unwrap();
      let transformed = re.replace_all(&wg_config, &replacement);

      fs::write(&disk_file, &*transformed)?;

      println!("Applied new configuration.");
    } else {
      println!("Config already up to date.");
    }

    Ok(())
}
