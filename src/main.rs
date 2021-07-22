use anyhow::{Result, bail};
use clap::{App, Arg};
use std::{
    fs::{self,File},
    io::{stdin, Read},
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
                .short('P')
                .takes_value(true)
                .about("public key file (default: ~/.pq-falcon-sigs/public.key)"),
        )
        .arg(
            Arg::new("secret-key")
                .short('Z')
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
                .short('D')
                .takes_value(true)
                .about("subject file"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .takes_value(true)
                .about("subject file"),
        )
        .arg(Arg::new("FILE").about("subject file").index(1))
        .get_matches();

    let mut reader: Box<dyn Read> = if let Some(filename) = matches.value_of("file") {
        Box::new(File::open(filename)?)
    } else if let Some(filename) = matches.value_of("FILE") {
        Box::new(File::open(filename)?)
    } else {
        Box::new(stdin())
    };

    let mut buf: Vec<u8> = Vec::new();

    let _n: usize = reader.read_to_end(&mut buf)?;

    println!("{:?}", String::from_utf8_lossy(&buf));

    match matches.value_of("degree") {
        Some(degree) if degree == "512" => {
            use pqcrypto_falcon::falcon512::keypair;
            use pqcrypto_falcon::falcon512::open;
            use pqcrypto_falcon::falcon512::sign;

            // TODO
        }
        None => {
            use pqcrypto_falcon::falcon1024::keypair;
            use pqcrypto_falcon::falcon1024::open;
            use pqcrypto_falcon::falcon1024::sign;

            
        if matches.is_present("keygen") {
            // TODO: CHECK OVERWRITE BEHAVIOR
            let (pk, sk) = keypair();
            fs::write("~/.pq-falcon-sigs/public.key", &pk)?;
            fs::write("~/.pq-falcon-sigs/secret.key", &sk)?;
        }

            // TODO READ PUB & SEC KEY


            if matches.is_present("sign") {
                // TODO SIGN
            } else {
                // TODO VERIFY
            }
        }
    };

    Ok(())
}
