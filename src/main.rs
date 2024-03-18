use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser};
use openssl::{
    encrypt::Decrypter,
    pkey::{Id, PKey, Private},
    rsa::Padding,
};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    str,
    time::Instant,
};

/// Calculate RSA PKCS1 decryption timing
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Key file
    #[arg(short = 'k', long)]
    key: String,

    /// Input file
    #[arg(short = 'i', long)]
    input: String,

    /// Output file
    #[arg(short = 'o', long)]
    output: String,

    /// Debug option to print the decrypted data to stdout
    #[arg(short = 's', long, action=ArgAction::SetTrue)]
    stdout: Option<bool>,
}

/// Open input and output files
fn open_files(input: &str, output: &str) -> Result<(File, File)> {
    let input_file = File::open(input).context("Failed to open input file")?;
    let output_file = File::create(output).context("Failed to create output file")?;
    Ok((input_file, output_file))
}

/// Get the decrypter set with PKCS1 padding
fn get_decrypter(pkey: &PKey<Private>) -> Result<Decrypter> {
    let mut decrypter = Decrypter::new(pkey).context("Failed to set decrypter key")?;

    decrypter
        .set_rsa_padding(Padding::PKCS1)
        .context("failed to set RSA decrypter padding")?;

    Ok(decrypter)
}

fn print_stdout(data: &Vec<u8>) {
    let r = str::from_utf8(&data);

    match r {
        Ok(s) => {
            print!("{s}\n");
        }
        Err(_) => {
            for b in data {
                print!("{b:02X?}");
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("input: {}", args.input);
    println!("output: {}", args.output);
    println!("keyfile: {}", args.key);

    let (input_file, mut output_file) = open_files(&args.input, &args.output)?;

    let mut reader = BufReader::new(input_file);

    let pkey =
        PKey::private_key_from_pem(&std::fs::read(&args.key).context("Failed to read key file")?)
            .context("Failed to parse private key from PEM file")?;

    if pkey.id() != Id::RSA {
        bail!("The provided key is not an RSA key");
    }

    let len: usize = pkey
        .rsa()
        .context("Failed getting RSA key from PKey")?
        .size()
        .try_into()
        .context("Failed to convert module lenght to usize")?;

    println!("key length: {} bits ({} bytes)", len * 8, len);

    let decrypter = get_decrypter(&pkey)?;

    let mut in_buf = vec![0; len];
    let mut out_buf = vec![0; len];

    let mut i = 0;

    while reader.read_exact(&mut in_buf).is_ok() {
        i = i + 1;
        let start = Instant::now();
        let res = decrypter.decrypt(&in_buf, &mut out_buf);
        let duration = start.elapsed();

        if res.is_err() {
            bail!("Failed to decrypt on iteration {i}");
        }

        if let Some(stdout) = args.stdout {
            if stdout {
                print_stdout(&out_buf);
            }
        }

        write!(&mut output_file, "{}\n", duration.as_nanos())
            .context("failed to write duration")?;

        if i % 10000 == 0 {
            println!("iteration {i}");
        }
    }

    if i == 0 {
        bail!("Failed to read input file: too small");
    }

    Ok(())
}
