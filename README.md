# pq-falcon-sigs

[![release](https://img.shields.io/github/v/release/chiefbiiko/pq-falcon-sigs?include_prereleases)](https://github.com/chiefbiiko/pq-falcon-sigs/releases/latest) [![GitHub license](https://img.shields.io/github/license/chiefbiiko/pq-falcon-sigs.svg)](https://github.com/chiefbiiko/pq-falcon-sigs/blob/main/LICENSE) [![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/chiefbiiko/pq-falcon-sigs)

CLI tool to sign and verify files with the post-quantum signature scheme [FALCON](https://falcon-sign.info/), a round 3 finalist for digital signature algorithms in NIST's post-quantum cryptography standardization competition

## Installation

**With `cargo`**

``` bash
cargo install --git https://github.com/chiefbiiko/pq-falcon-sigs#0.1.1
```

The tool will come available on your command line as `falcon`

**Or `curl`**

``` bash
release_url=https://github.com/chiefbiiko/pq-falcon-sigs/releases/download/v0.1.1/pq-falcon-sigs-v0.1.1-x86_64-unknown-linux-gnu.gz

curl -fsSL $release_url | gunzip > /usr/local/bin/falcon
chmod u+x /usr/local/bin/falcon
```

Find current prebuilds for Linux, and macOS ~~, Windows~~ on the [releases page](https://github.com/chiefbiiko/pq-falcon-sigs/releases/latest)

## Usage

```
pq-falcon-sigs 0.1.1
chiefbiiko <hello@nugget.digital>
Sign and verify files with the post-quantum signature scheme FALCON

USAGE:
    falcon [FLAGS] [OPTIONS] [FILE]

ARGS:
    <FILE>    Input file

FLAGS:
    -F, --force      Overwrites possibly existing key files
    -h, --help       Prints help information
    -K, --keygen     Generates a fresh FALCON keypair
    -O, --open       Verifies a file
    -S, --sign       Signs a file
    -V, --version    Prints version information

OPTIONS:
    -d <degree>                 512 or 1024; default 1024
    -f <file>                   Input file
    -o <output>                 Output file
    -k <public-key>             Base64 public key
    -p <public-key-file>        Public key file; default: ~/.pq-falcon-sigs/public.key
    -s <secret-key-file>        Secret key file; default: ~/.pq-falcon-sigs/secret.key

If no input/output file(s) are given stdin/stdout are used for IO
```

## License

[MIT](./LICENSE)