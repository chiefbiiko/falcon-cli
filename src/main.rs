use anyhow::{anyhow, Result};
use clap::{App, Arg, ArgMatches};
use pqcrypto_falcon::{falcon1024, falcon512};
use pqcrypto_traits::sign::{
    PublicKey, SecretKey, SignedMessage, VerificationError,
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

fn dump_output(matches: &ArgMatches, bytes: &[u8]) -> Result<()> {
    if let Some(output) = matches.value_of("output") {
        let output_exists = Path::new(output).exists();
        if !output_exists || (output_exists && matches.is_present("force")) {
            fs::write(output, bytes)?;
            Ok(())
        } else {
            Err(anyhow!("not overwriting existing output file"))
        }
    } else {
        io::stdout().write(bytes)?;
        Ok(())
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
            Box::new(io::stdin())
        };
    let mut file_buf: Vec<u8> = Vec::new();
    // TODO: enforce a read timeout of ~1s, if then stdin still empty bail
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
                    fs::write(pk_file, (&pk).as_bytes())?;
                } else if pk_file_exists && !matches.is_present("force") {
                    return Err(anyhow!(
                        "not overwriting existing public key file"
                    ));
                }
                if !sk_file_exists
                    || (sk_file_exists && matches.is_present("force"))
                {
                    fs::write(sk_file, (&sk).as_bytes())?;
                    fs::set_permissions(
                        sk_file,
                        fs::Permissions::from_mode(0o600),
                    )?;
                } else if sk_file_exists && !matches.is_present("force") {
                    return Err(anyhow!(
                        "not overwriting existing secret key file"
                    ));
                }

                return Ok(());
            }

            if matches.is_present("sign") {
                let sk_buf = fs::read(sk_file)?;
                let sk = falcon1024::SecretKey::from_bytes(&sk_buf)?;

                let signed_msg = falcon1024::sign(&file_buf, &sk);

                dump_output(&matches, signed_msg.as_bytes())?;
            } else {
                let pk_buf = fs::read(pk_file)?;
                let pk = falcon1024::PublicKey::from_bytes(&pk_buf)?;
                let signed_msg =
                    falcon1024::SignedMessage::from_bytes(&file_buf)?;

                let verified_file = falcon1024::open(&signed_msg, &pk)
                    .map_err(|_| VerificationError::InvalidSignature)?;

                dump_output(&matches, &verified_file)?;
            }
        }
    };

    Ok(())
}
