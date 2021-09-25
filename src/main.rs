use anyhow::{anyhow, bail, Result};
use atty::Stream;
use base64;
use clap::{App, Arg, ArgMatches};
use pqcrypto_falcon::{falcon1024, falcon512};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

fn keygen(clap: &ArgMatches, pk_file: &Path, sk_file: &Path) -> Result<()> {
    let (pk, sk): (Box<dyn PublicKey>, Box<dyn SecretKey>) =
        if clap.value_of("degree") == Some("512") {
            let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
            (Box::new(pk), Box::new(sk))
        } else {
            let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
            (Box::new(pk), Box::new(sk))
        };

    let key_dir = sk_file.parent().unwrap_or(Path::new("/"));
    let pk_file_exists = pk_file.exists();
    let sk_file_exists = sk_file.exists();

    if !pk_file_exists || (pk_file_exists && clap.is_present("force")) {
        fs::create_dir_all(&key_dir)?;
        fs::write(&pk_file, pk.as_bytes())?;
    } else if pk_file_exists && !clap.is_present("force") {
        bail!("not overwriting existing public key file");
    }

    if !sk_file_exists || (sk_file_exists && clap.is_present("force")) {
        fs::create_dir_all(&key_dir)?;
        fs::write(&sk_file, sk.as_bytes())?;
        #[cfg(not(target_os = "windows"))]
        fs::set_permissions(&sk_file, fs::Permissions::from_mode(0o600))?;
    } else if sk_file_exists && !clap.is_present("force") {
        bail!("not overwriting existing secret key file");
    }

    Ok(())
}

fn dump_output(clap: &ArgMatches, bytes: &[u8]) -> Result<()> {
    if let Some(output) = clap.value_of("output") {
        let output_exists = Path::new(output).exists();

        if !output_exists || (output_exists && clap.is_present("force")) {
            fs::write(output, bytes)?;
        } else {
            bail!("not overwriting existing output file");
        }
    } else {
        io::stdout().write(bytes)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let clap = App::new("falcon-cli")
        .version("0.1.2")
        .author("chiefbiiko <hello@nugget.digital>")
        .about("Sign and verify files with the post-quantum signature scheme FALCON")
        .after_help("If no input/output file(s) are given stdin/stdout are used for IO")
        .after_long_help("If no input/output file(s) are given stdin/stdout are used for IO")
        .arg(
            Arg::new("keygen")
                .short('K')
                .long("keygen")
                .takes_value(false)
                .about("Generates a fresh FALCON keypair"),
        )
        .arg(
            Arg::new("public-key")
                .short('k')
                .takes_value(true)
                .about("Base64 public key"),
        )
        .arg(
            Arg::new("public-key-file")
                .short('p')
                .takes_value(true)
                .about("Public key file; default: ~/.falcon-cli/public.key"),
        )
        .arg(
            Arg::new("secret-key-file")
                .short('s')
                .takes_value(true)
                .about("Secret key file; default: ~/.falcon-cli/secret.key"),
        )
        .arg(
            Arg::new("open")
                .short('O')
                .long("open")
                .takes_value(false)
                .about("Verifies a file"),
        )
        .arg(
            Arg::new("sign")
                .short('S')
                .long("sign")
                .takes_value(false)
                .about("Signs a file"),
        )
        .arg(
            Arg::new("degree")
                .short('d')
                .takes_value(true)
                .about("512 or 1024; default 1024"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .takes_value(true)
                .about("Input file"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .takes_value(true)
                .about("Output file"),
        )
        .arg(
            Arg::new("force")
                .short('F')
                .long("force")
                .takes_value(false)
                .about("Overwrites possibly existing key files"),
        )
        .arg(Arg::new("FILE").about("Input file").index(1))
        .get_matches();

    let home_dir = home::home_dir().ok_or(anyhow!("cannot find home dir"))?;
    let pk_file = clap
        .value_of("public-key-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir.join(".falcon-cli/public.key"));
    let sk_file = clap
        .value_of("secret-key-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir.join(".falcon-cli/secret.key"));

    if clap.is_present("keygen") {
        keygen(&clap, pk_file.as_path(), sk_file.as_path())?;
        return Ok(());
    }

    let mut file_buf: Vec<u8> = Vec::new();
    let mut file_rdr: Box<dyn Read> =
        if let Some(filename) = clap.value_of("file") {
            Box::new(File::open(filename)?)
        } else if let Some(filename) = clap.value_of("FILE") {
            Box::new(File::open(filename)?)
        } else {
            if atty::is(Stream::Stdin) {
                bail!("no incoming data in stdin")
            }
            Box::new(io::stdin())
        };
    let _n = file_rdr.read_to_end(&mut file_buf)?;

    match clap.value_of("degree") {
        Some(degree) if degree == "512" => {
            if clap.is_present("sign") {
                let sk_buf = fs::read(sk_file)?;
                let sk = falcon512::SecretKey::from_bytes(&sk_buf)?;

                let signed_msg = falcon512::sign(&file_buf, &sk);

                dump_output(&clap, signed_msg.as_bytes())?;
            } else {
                let pk_buf = if clap.is_present("public-key") {
                    base64::decode(clap.value_of("public-key").unwrap())?
                } else {
                    fs::read(pk_file)?
                };
                let pk = falcon512::PublicKey::from_bytes(&pk_buf)?;
                let signed_msg =
                    falcon512::SignedMessage::from_bytes(&file_buf)?;

                let verified_file = falcon512::open(&signed_msg, &pk)
                    .map_err(|_| anyhow!("verification failed"))?;

                dump_output(&clap, &verified_file)?;
            }
        }
        Some(_) | None => {
            if clap.is_present("sign") {
                let sk_buf = fs::read(sk_file)?;
                let sk = falcon1024::SecretKey::from_bytes(&sk_buf)?;

                let signed_msg = falcon1024::sign(&file_buf, &sk);

                dump_output(&clap, signed_msg.as_bytes())?;
            } else {
                let pk_buf = if clap.is_present("public-key") {
                    base64::decode(clap.value_of("public-key").unwrap())?
                } else {
                    fs::read(pk_file)?
                };
                let pk = falcon1024::PublicKey::from_bytes(&pk_buf)?;
                let signed_msg =
                    falcon1024::SignedMessage::from_bytes(&file_buf)?;

                let verified_file = falcon1024::open(&signed_msg, &pk)
                    .map_err(|_| anyhow!("verification failed"))?;

                dump_output(&clap, &verified_file)?;
            }
        }
    };

    Ok(())
}
