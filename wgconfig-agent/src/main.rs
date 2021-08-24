extern crate crypto;
extern crate reqwest;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
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

    println!("{}", wg_config);

    let mut hasher = Sha256::new();
    hasher.input_str(&wg_config);
    let hex = hasher.result_str();

    println!("hash = {}", hex);

    let disk_file = "./wg-test.conf";
    let mut current = Path::new(&disk_file).exists();

    if current {
      let contents = fs::read_to_string(&disk_file)
          .expect("Something went wrong reading the file");

      println!("{}", contents);

      hasher = Sha256::new();
      hasher.input_str(&contents);
      let newhex = hasher.result_str();
      println!("newhash = {}", newhex);

      current = hex == newhex;
    }

    if !current {
      fs::write(&disk_file, &wg_config)?;
    }

    println!("Current = {}", current);

    Ok(())
}
