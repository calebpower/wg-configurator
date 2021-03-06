/*
 * Copyright (c) 2021 Caleb L. Power. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for specific language governing permissions and
 * limitations under the License.
 */

extern crate crypto;
extern crate quit;
extern crate regex;
extern crate reqwest;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use regex::Regex;
use std::env;
use std::fs;
use std::path::Path;

#[tokio::main]
#[quit::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args: Vec<String> = env::args().collect();
  assert_eq!(args.len(), 5, "Please specify four (4) args: <upstream> <host> <privkey> <config>");

  //println!("upstream = {}\nhost = {}\nprivkey = {}\nconfig = {}", &args[1], &args[2], &args[3], &args[4]);

  // to start, pull the most current config

  let client = reqwest::Client::builder()
      .build()?;

  let mut remote_config = args[1].to_owned();
  remote_config.push_str("/hosts/");
  remote_config.push_str(&args[2]);

  let res = client
      .get(&remote_config)
      .send()
      .await?;

  let wg_config = res
      .text()
      .await?;

  // go ahead and replace the privkey template with the actual privkey
  let mut replacement = "PrivateKey = ".to_owned();
  replacement.push_str(&args[3]);
  replacement.push_str("\n");

  let re = Regex::new("PrivateKey\\s*=.*\n").unwrap();
  let transformed = re.replace_all(&wg_config, &replacement);

  // then hash it
  let mut hasher = Sha256::new();
  hasher.input_str(&transformed);
  let remote_hex = hasher.result_str();

  println!("Network Config SHA256 = {}", remote_hex);

  // now, start looking at the config on the disk... first, see if it exists

  let mut current = Path::new(&args[4]).exists();

  // if it doesn't exist, then it's obviously not current
  // if it does exist, it's considered current (for now)

  if current {
    // so, read the file
    let contents = fs::read_to_string(&args[4])
        .expect("Something went wrong reading the file");

    // hash the on-disk config file, which should already have the privkey
    hasher = Sha256::new();
    hasher.input_str(&contents);
    let local_hex = hasher.result_str();
    println!("Current Config SHA256 = {}", local_hex);

    // ultimately, disk file is current iff the hashes match
    current = local_hex == remote_hex;
  }

  if !current {
    fs::write(&args[4], &*transformed)?;

    println!("Applied new configuration.");
  } else {
    println!("Config already up to date.");
    quit::with_code(2);
  }

  Ok(())
}
