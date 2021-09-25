# falcon-cli

[![release](https://img.shields.io/github/v/release/chiefbiiko/falcon-cli?include_prereleases)](https://github.com/chiefbiiko/falcon-cli/releases/latest) [![GitHub license](https://img.shields.io/github/license/chiefbiiko/falcon-cli.svg)](https://github.com/chiefbiiko/falcon-cli/blob/main/LICENSE) [![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/chiefbiiko/falcon-cli)

CLI tool to sign and verify files with the post-quantum signature scheme [FALCON](https://falcon-sign.info/), a round 3 finalist for digital signature algorithms in NIST's post-quantum cryptography standardization competition

## Installation

**With `cargo`**

``` bash
cargo install --git https://github.com/chiefbiiko/falcon-cli#0.1.2
```

The tool will come available on your command line as `falcon`

To install and compile successfully make sure you are at least using `rustc 1.55.0`

**Or `curl`**

``` bash
release_url=https://github.com/chiefbiiko/falcon-cli/releases/download/v0.1.2/falcon-cli-v0.1.1-x86_64-unknown-linux-gnu.gz

curl -fsSL $release_url | gunzip > /usr/local/bin/falcon
chmod u+x /usr/local/bin/falcon
```

Find current prebuilds for Linux, and macOS ~~, Windows~~ on the [releases page](https://github.com/chiefbiiko/falcon-cli/releases/latest)

## Usage

If not havin' generated a key pair yet (default location `~/.falcon-cli`) do it now

```bash
🌍 ~/falcon-demo 🎹 falcon --keygen
```

A test file to roundtrip

```bash
🌍 ~/falcon-demo 🎹 echo "msg 2 sign safely post quantum" > file.txt
```

Signin' and openin' - here we are explcititely referencin' the secret and public key with the `-s` and `-p` options respectively

```bash
🌍 ~/falcon-demo 🎹 falcon -S -o signed.txt -s ~/.falcon-cli/secret.key ./file.txt
🌍 ~/falcon-demo 🎹 falcon -O -o opened.txt -p ~/.falcon-cli/public.key ./signed.txt
```

Outcome

```bash
🌍 ~/falcon-demo 🎹 cmp ./opened.txt ./file.txt
🌍 ~/falcon-demo 🎹 cat ./opened.txt ./file.txt
msg 2 sign safely post quantum
msg 2 sign safely post quantum
```

## Docs

```
falcon-cli 0.1.2
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
    -p <public-key-file>        Public key file; default: ~/.falcon-cli/public.key
    -s <secret-key-file>        Secret key file; default: ~/.falcon-cli/secret.key

If no input/output file(s) are given stdin/stdout are used for IO
```

## License

[MIT](./LICENSE)