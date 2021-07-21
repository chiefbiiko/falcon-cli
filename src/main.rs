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

    if let Some(val) = matches.value_of("file") {
        println!("value for file: {}", val);

        if matches.is_present("sign") {
            // TODO SIGN
        } else {
            // TODO VERIFY
        }
    } else {
        // TODO CHECK STDIN ELSE ERROR NO_FILE
    }
}
