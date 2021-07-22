use clap::{App, Arg};

fn main() {
    let matches = App::new("pq-falcon-sigs")
        .version("0.0.0")
        .author("Noah A. Schwarz <noah.anabiik.schwarz@gmail.com>")
        .about("Sign and verify files with the post-quantum signature scheme FALCON")
        .arg(
            Arg::new("V")
                .short("verify")
                .takes_value(false)
                .about("Verifies a file"),
        )
        .arg(
            Arg::new("S")
                .short("sign")
                .takes_value(false)
                .about("Verifies a file"),
        )
        .arg(
            Arg::new("file")
                .short("f")
                .takes_value(true)
                .about("The subject file"),
        )
        .get_matches();

    let reader: Box<BufReader> = if let Some(filename) = matches.value_of("file") {
        Box::new(BufReader::new(
            fs::File::open(filename).expect("fopen failed"),
        ))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };

    let bytes: Vec<u8> = reader.lines().collect::<Result<_, _>>().unwrap();

    println!(&String::from_utf8_lossy(bytes).unwrap());

    if matches.is_present("sign") {
        // TODO SIGN
    } else {
        // TODO VERIFY
    }
}
