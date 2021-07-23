use anyhow::{anyhow, Result};
use clap::{App, Arg};
use pqcrypto_falcon::{falcon1024::*, falcon512::*};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use std::{
    fs::{self, File},
    io::{self, Read},
};

fn main() -> Result<()> {
    let matches = App::new("pq-falcon-sigs")
        .version("0.0.0")
        .author("Noah Anabiik Schwarz <noah.anabiik.schwarz@gmail.com>")
        .about("sign and verify files with the post-quantum signature scheme FALCON")
        .arg(
            Arg::new("keygen")
                .short('K')
                .takes_value(false)
                .about("generates a fresh FALCON keypair"),
        )
        .arg(
            Arg::new("public-key")
                .short('k')
                .takes_value(true)
                .about("base64 public key"),
        )
        .arg(
            Arg::new("public-key-file")
                .short('p')
                .takes_value(true)
                .about("public key file (default: ~/.pq-falcon-sigs/public.key)"),
        )
        .arg(
            Arg::new("secret-key-file")
                .short('s')
                .takes_value(true)
                .about("secret key file (default: ~/.pq-falcon-sigs/secret.key)"),
        )
        .arg(
            Arg::new("open")
                .short('O')
                .takes_value(false)
                .about("verifies a file"),
        )
        .arg(
            Arg::new("sign")
                .short('S')
                .takes_value(false)
                .about("signs a file"),
        )
        .arg(
            Arg::new("degree")
                .short('d')
                .takes_value(true)
                .about("subject file"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .takes_value(true)
                .about("subject file"),
        )
        .arg(
            Arg::new("force")
                .short('F')
                .takes_value(false)
                .about("i.e. overwrite possibly existing key files"),
        )
        .arg(Arg::new("FILE").about("subject file").index(1))
        .get_matches();

    let mut reader: Box<dyn Read> =
        if let Some(filename) = matches.value_of("file") {
            Box::new(File::open(filename)?)
        } else if let Some(filename) = matches.value_of("FILE") {
            Box::new(File::open(filename)?)
        } else {
            // TODO: assert stdin has input
            Box::new(io::stdin())
        };
    let mut buf: Vec<u8> = Vec::new();
    let _n: usize = reader.read_to_end(&mut buf)?;

    let home_dir = home::home_dir().ok_or(anyhow!("cannot find home dir"))?;
    let default_public_key_file = format!(
        "{}/.pq-falcon-sigs/public.key",
        &home_dir.as_path().display()
    );
    let default_secret_key_file = format!(
        "{}/.pq-falcon-sigs/secret.key",
        &home_dir.as_path().display()
    );
    let public_key_file = matches
        .value_of("public-key")
        .unwrap_or(&default_public_key_file);
    let secret_key_file = matches
        .value_of("secret-key")
        .unwrap_or(&default_secret_key_file);

    match matches.value_of("degree") {
        Some(degree) if degree == "512" => {
            // TODO
        }
        Some(_) | None => {
            if matches.is_present("keygen") {
                // TODO: CHECK OVERWRITE BEHAVIOR
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
                fs::write(public_key_file, (&pk).as_bytes())?;
                // TODO: write with narrow permissions
                fs::write(secret_key_file, (&sk).as_bytes())?;
                return Ok(());
            }

            // TODO READ PUB & SEC KEY
            // println!("public_key_file {:?}", public_key_file);
            // let public_key_buf = fs::read(public_key_file)?;
            // println!("&pubbuf {:?}", String::from_utf8_lossy(&public_key_buf));
            // let secret_key_buf = fs::read(secret_key_file)?;
            // let pk = PublicKey::from_bytes(&public_key_buf)?;
            // let sk = SecretKey::from(&fs::read(secret_key_file)?)?;

            // use pqcrypto_falcon::falcon1024::open;
            // use pqcrypto_falcon::falcon1024::sign;
            if matches.is_present("sign") {
                let secret_key_buf = fs::read(secret_key_file)?;
                println!("{:?}", &secret_key_buf);
                // TODO SIGN
            } else {
                let public_key_buf = fs::read(public_key_file)?;
                println!("{:?}", &public_key_buf);
                // TODO VERIFY
            }
        }
    };

    Ok(())
}
