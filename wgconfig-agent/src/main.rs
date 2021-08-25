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
    let client = reqwest::Client::builder()
        .build()?;

    let res = client
        .get("http://127.0.0.1:10000/hosts/home-pc")
        .send()
        .await?;

    let wg_config = res
        .text()
        .await?;

    println!("Net config:\n\n{}", wg_config);

    let mut hasher = Sha256::new();
    hasher.input_str(&wg_config);
    let hex = hasher.result_str();

    println!("hash = {}", hex);

    let disk_file = "./wg-test.conf";
    let mut current = Path::new(&disk_file).exists();

    let private_key = "MY_PRIVKEY";

    if current {
      let contents = fs::read_to_string(&disk_file)
          .expect("Something went wrong reading the file");

      println!("Disk config:\n\n{}", contents);

      let mut regstr = "PrivateKey\\s*=\\s*".to_owned();
      regstr.push_str(&private_key);
      regstr.push_str("\n");

      let re = Regex::new(&regstr).unwrap();
      let transformed = re.replace_all(&contents, "PrivateKey = {{ PRIVATE_KEY }}\n");
      println!("Redacted disk config:\n\n{}", &transformed);

      hasher = Sha256::new();
      hasher.input_str(&transformed);
      let newhex = hasher.result_str();
      println!("newhash = {}", newhex);

      current = hex == newhex;
    }

    if !current {
      let mut replacement = "PrivateKey = ".to_owned();
      replacement.push_str(&private_key);
      replacement.push_str("\n");

      let re = Regex::new("PrivateKey\\s*=.*\n").unwrap();
      let transformed = re.replace_all(&wg_config, &replacement);

      println!("Applied net config:\n\n{}", &transformed);

      fs::write(&disk_file, &*transformed)?;
    }

    println!("Current = {}", current);

    Ok(())
}
