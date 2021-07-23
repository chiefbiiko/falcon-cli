use anyhow::{anyhow, Result};
use clap::{App, Arg};
use pqcrypto_falcon::{falcon1024, falcon512, ffi};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

struct Falcon1024PublicKey(u8);

impl PublicKey for Falcon1024PublicKey {
    as_bytes(&self) -> &[u8] {
        self.0.as_ptr()
    }
    from_bytes(bytes: &[u8]) -> Result<Falcon1024PublicKey> {
        // TODO: from slice to tuple struct
    }
}

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
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();

                let public_key_file_exists =
                    Path::new(public_key_file).exists();
                let secret_key_file_exists =
                    Path::new(secret_key_file).exists();

                if !public_key_file_exists
                    || (public_key_file_exists && matches.is_present("force"))
                {
                    // TODO: ASSERT OVERWRITE WHEN FILE EXISTS
                    fs::write(public_key_file, (&pk).as_bytes())?;
                } else if public_key_file_exists && !matches.is_present("force")
                {
                    println!(
                        "WARNING: not overwriting existing public key file"
                    )
                }
                if !secret_key_file_exists
                    || (secret_key_file_exists && matches.is_present("force"))
                {
                    // TODO: write with narrow permissions & ASSERT OVERWRITE WHEN FILE EXISTS
                    fs::write(secret_key_file, (&sk).as_bytes())?;
                } else if secret_key_file_exists && !matches.is_present("force")
                {
                    println!(
                        "WARNING: not overwriting existing secret key file"
                    )
                }

                return Ok(());
            }

            if matches.is_present("sign") {
                let secret_key_buf = fs::read(secret_key_file)?;
                println!("{:?}", &secret_key_buf);

                assert_eq!(secret_key_buf.len(), ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES);
                // TODO SIGN
            } else {
                let public_key_buf = fs::read(public_key_file)?;
                println!("{:?}", &public_key_buf);

                assert_eq!(public_key_buf.len(), ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES);

                let pk = Falcon1024PublicKey::from_bytes(&public_key_buf)?;
                // TODO VERIFY
            }
        }
    };

    Ok(())
}
