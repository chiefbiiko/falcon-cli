use anyhow::{anyhow, Result};
use clap::{App, Arg};
use pqcrypto_falcon::{falcon1024, falcon512, ffi};
use pqcrypto_traits::{
    sign::{PublicKey, SecretKey, VerificationError},
    Error as PQError,
};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct Falcon1024PublicKey(
    [u8; ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
);

#[derive(Clone)]
pub struct Falcon1024SecretKey(
    [u8; ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES],
);

impl PublicKey for Falcon1024PublicKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn from_bytes(bytes: &[u8]) -> Result<Falcon1024PublicKey, PQError> {
        Ok(Falcon1024PublicKey(
            <[u8; ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES]>
            ::try_from(bytes)
            .map_err(|_| PQError::BadLength {
                name: "InvalidPublicKeyBytes",
                actual: bytes.len(),
                expected: ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            })?
        ))
    }
}

impl SecretKey for Falcon1024SecretKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn from_bytes(bytes: &[u8]) -> Result<Falcon1024SecretKey, PQError> {
        Ok(Falcon1024SecretKey(
            <[u8; ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES]>
            ::try_from(bytes)
            .map_err(|_| PQError::BadLength {
                name: "InvalidSecretKeyBytes",
                actual: bytes.len(),
                expected: ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES
            })?
        ))
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
                .about("either 512 or 1024"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .takes_value(true)
                .about("input file"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .takes_value(true)
                .about("output file path"),
        )
        .arg(
            Arg::new("force")
                .short('F')
                .takes_value(false)
                .about("i.e. overwrite possibly existing key files"),
        )
        .arg(Arg::new("FILE").about("subject file").index(1))
        .get_matches();

    let mut file_rdr: Box<dyn Read> =
        if let Some(filename) = matches.value_of("file") {
            Box::new(File::open(filename)?)
        } else if let Some(filename) = matches.value_of("FILE") {
            Box::new(File::open(filename)?)
        } else {
            // TODO: assert stdin has input
            Box::new(io::stdin())
        };
    let mut file_buf: Vec<u8> = Vec::new();
    let _n: usize = file_rdr.read_to_end(&mut file_buf)?;

    let home_dir = home::home_dir().ok_or(anyhow!("cannot find home dir"))?;
    let default_pk_file = format!(
        "{}/.pq-falcon-sigs/public.key",
        &home_dir.as_path().display()
    );
    let default_sk_file = format!(
        "{}/.pq-falcon-sigs/secret.key",
        &home_dir.as_path().display()
    );
    let pk_file = matches.value_of("public-key").unwrap_or(&default_pk_file);
    let sk_file = matches.value_of("secret-key").unwrap_or(&default_sk_file);

    match matches.value_of("degree") {
        Some(degree) if degree == "512" => {
            // TODO
        }
        Some(_) | None => {
            if matches.is_present("keygen") {
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();

                let pk_file_exists = Path::new(pk_file).exists();
                let sk_file_exists = Path::new(sk_file).exists();

                if !pk_file_exists
                    || (pk_file_exists && matches.is_present("force"))
                {
                    // TODO: ASSERT OVERWRITE WHEN FILE EXISTS
                    fs::write(pk_file, (&pk).as_bytes())?;
                } else if pk_file_exists && !matches.is_present("force") {
                    println!(
                        "WARNING: not overwriting existing public key file"
                    )
                }
                if !sk_file_exists
                    || (sk_file_exists && matches.is_present("force"))
                {
                    // TODO: write with narrow permissions & ASSERT OVERWRITE WHEN FILE EXISTS
                    fs::write(sk_file, (&sk).as_bytes())?;
                } else if sk_file_exists && !matches.is_present("force") {
                    println!(
                        "WARNING: not overwriting existing secret key file"
                    )
                }

                return Ok(());
            }

            if matches.is_present("sign") {
                let sk_buf = fs::read(sk_file)?;
                let sk = Falcon1024SecretKey::from_bytes(&sk_buf)?;
                // println!("$$$$$ sk\n{:?}", &sk);

                let signed_msg = falcon1024::sign(&file_buf, &sk);
                // TODO SIGN
            } else {
                let pk_buf = fs::read(pk_file)?;
                let pk = Falcon1024PublicKey::from_bytes(&pk_buf)?;
                let signed_msg = falcon1024::SignedMessage(file_buf);

                let verified_file = falcon1024::open(&signed_msg, &pk)
                    .map_err(|_| VerificationError::InvalidSignature)?;

                if let Some(output_path) = matches.value_of("output") {
                    let output_path_exists = Path::new(output_path).exists();

                    if !output_path_exists
                        || (output_path_exists && matches.is_present("force"))
                    {
                        // TODO: ASSERT OVERWRITE WHEN FILE EXISTS
                        fs::write(output_path, &verified_file)?;
                    } else if output_path_exists && !matches.is_present("force")
                    {
                        println!(
                            "WARNING: not overwriting existing output file"
                        )
                    }
                } else {
                    // TODO: write verified_file to stdout
                    io::stdout().write(&verified_file)?
                }

                Ok(()) // exit 0
            }
        }
    };

    Ok(())
}
