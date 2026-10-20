use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand_core::OsRng;
use stegpony_core::jpeg::carrier as jpeg;
use stegpony_core::lossless::{self, SourceFormat};
use stegpony_core::text;
use stegpony_core::{Detectability, HideKey, Identity, Payload, Recipient, RevealKey};
use zeroize::Zeroizing;

/// Hide encrypted messages and files in images and text.
#[derive(Parser)]
#[command(name = "stegpony", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hide a message or file in a cover image.
    Hide(HideArgs),
    /// Look for a hidden message or file.
    Reveal(RevealArgs),
    /// Show how much a cover can hold.
    Capacity {
        /// Cover image (PNG or JPEG).
        cover: PathBuf,
        /// Carrier mode.
        #[arg(long, value_enum, default_value = "lossless")]
        mode: ImageMode,
    },
    /// Generate an identity (age X25519 key pair).
    Keygen {
        /// Write the identity to this file instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ImageMode {
    Lossless,
    Jpeg,
    /// Words from the English list (no cover needed).
    Words,
    /// Invisible characters in a cover message (the cover is a UTF-8 text file).
    ZeroWidth,
}

#[derive(Args)]
struct HideArgs {
    /// Cover image (PNG or JPEG), or for zero-width mode a UTF-8 text file holding
    /// the visible message. Not used in words mode.
    #[arg(short, long)]
    cover: Option<PathBuf>,
    /// Output file (PNG in lossless mode, JPEG in jpeg mode, UTF-8 text otherwise).
    #[arg(short, long)]
    output: PathBuf,
    /// Carrier mode.
    #[arg(long, value_enum, default_value = "lossless")]
    mode: ImageMode,
    /// Keep JPEG metadata, including location information.
    #[arg(long)]
    keep_metadata: bool,
    #[command(flatten)]
    payload: PayloadArgs,
    /// Hide for this recipient instead of a passphrase: an age1... string, or a file
    /// holding a Curve25519 OpenPGP key.
    #[arg(short, long)]
    recipient: Option<String>,
    /// Decoy text, revealed by the decoy secret.
    #[arg(long, conflicts_with = "decoy_file")]
    decoy_message: Option<String>,
    /// Decoy file, revealed by the decoy secret.
    #[arg(long)]
    decoy_file: Option<PathBuf>,
    /// Hide the decoy for this recipient (age1... or OpenPGP key file) instead of a
    /// decoy passphrase.
    #[arg(long)]
    decoy_recipient: Option<String>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct PayloadArgs {
    /// Text to hide.
    #[arg(short, long)]
    message: Option<String>,
    /// File to hide.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Args)]
struct RevealArgs {
    /// Image or UTF-8 text file to look in.
    image: PathBuf,
    /// Identity file(s) to try: age identity files or Curve25519 OpenPGP secret keys
    /// (their passphrase is prompted for, or read from STEGPONY_PGP_PASSPHRASE).
    #[arg(short, long)]
    identity: Vec<PathBuf>,
    /// Also ask for a passphrase (the default when no identity is given).
    #[arg(short, long)]
    passphrase: bool,
    /// Directory to write a revealed file into.
    #[arg(short, long, default_value = ".")]
    out_dir: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Hide(a) => hide(a),
        Cmd::Reveal(a) => reveal(a),
        Cmd::Capacity { cover, mode } => capacity(&cover, mode),
        Cmd::Keygen { output } => keygen(output),
    }
}

/// Passphrases come from an environment variable when set (for scripts and tests),
/// otherwise from a prompt with confirmation.
fn passphrase(env: &str, prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(v) = std::env::var(env) {
        let v = Zeroizing::new(v);
        if v.is_empty() {
            bail!("{env} is set but empty");
        }
        return Ok(v);
    }
    let p = Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?);
    if p.is_empty() {
        bail!("empty passphrase");
    }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password(format!("{prompt} (again): "))?);
        if *again != *p {
            bail!("passphrases did not match");
        }
    }
    Ok(p)
}

fn load_payload(message: Option<String>, file: Option<PathBuf>) -> Result<Payload> {
    if let Some(m) = message {
        return Ok(Payload::Text(m));
    }
    let path = file.context("nothing to hide")?;
    let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Payload::File {
        name,
        mime: "application/octet-stream".into(),
        data,
    })
}

fn hide(a: HideArgs) -> Result<()> {
    let has_decoy = a.decoy_message.is_some() || a.decoy_file.is_some();
    if a.decoy_recipient.is_some() && !has_decoy {
        bail!("--decoy-recipient needs --decoy-message or --decoy-file");
    }
    let cover = match (&a.cover, a.mode) {
        (_, ImageMode::Words) => Vec::new(),
        (Some(path), _) => fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        (None, _) => bail!("--cover is required in this mode"),
    };
    let payload = load_payload(a.payload.message, a.payload.file)?;
    let key = match a.recipient {
        Some(r) => HideKey::Recipient(parse_recipient(&r)?),
        None => HideKey::Passphrase(passphrase("STEGPONY_PASSPHRASE", "Passphrase", true)?),
    };
    let decoy = if has_decoy {
        let p = load_payload(a.decoy_message, a.decoy_file)?;
        let k = match a.decoy_recipient {
            Some(r) => HideKey::Recipient(parse_recipient(&r)?),
            None => HideKey::Passphrase(passphrase(
                "STEGPONY_DECOY_PASSPHRASE",
                "Decoy passphrase",
                true,
            )?),
        };
        Some((p, k))
    } else {
        None
    };

    let (bytes, detectability) = match a.mode {
        ImageMode::Lossless => {
            if a.keep_metadata {
                bail!("--keep-metadata requires --mode jpeg");
            }
            let out = lossless::hide(
                &cover,
                (&payload, &key),
                decoy.as_ref().map(|(p, k)| (p, k)),
                &mut OsRng,
            )?;
            if out.source == SourceFormat::Jpeg {
                eprintln!("note: the cover was a JPEG; the output is a PNG, which is unusual for a camera photo");
            }
            (out.png, out.detectability)
        }
        ImageMode::Jpeg => {
            let out = jpeg::hide(
                &cover,
                (&payload, &key),
                decoy.as_ref().map(|(p, k)| (p, k)),
                a.keep_metadata,
                &mut OsRng,
            )?;
            (out.jpeg, out.detectability)
        }
        ImageMode::Words | ImageMode::ZeroWidth => {
            if a.keep_metadata {
                bail!("--keep-metadata requires --mode jpeg");
            }
            let (mode, cover) = if matches!(a.mode, ImageMode::Words) {
                (text::TextMode::Dictionary, String::new())
            } else {
                let cover = String::from_utf8(cover).context("the cover text is not UTF-8")?;
                (text::TextMode::ZeroWidth, cover)
            };
            let out = text::hide(
                mode,
                &cover,
                (&payload, &key),
                decoy.as_ref().map(|(p, k)| (p, k)),
                &mut OsRng,
            )?;
            fs::write(&a.output, out.as_bytes())
                .with_context(|| format!("writing {}", a.output.display()))?;
            eprintln!("wrote {}", a.output.display());
            return Ok(());
        }
    };
    fs::write(&a.output, bytes).with_context(|| format!("writing {}", a.output.display()))?;
    let d = match detectability {
        Detectability::Low => "low",
        Detectability::Medium => "medium",
        Detectability::High => "high (use a larger cover or a smaller payload)",
    };
    let label = match a.mode {
        ImageMode::Lossless => "provisional detectability",
        ImageMode::Jpeg => "detectability",
        ImageMode::Words | ImageMode::ZeroWidth => unreachable!(),
    };
    eprintln!("wrote {} ({label}: {d})", a.output.display());
    Ok(())
}

fn reveal(a: RevealArgs) -> Result<()> {
    let image = fs::read(&a.image).with_context(|| format!("reading {}", a.image.display()))?;
    let mut keys = Vec::new();
    for path in &a.identity {
        let bytes =
            Zeroizing::new(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
        let text = std::str::from_utf8(&bytes).ok();
        if let Some(Ok(ids)) = text.map(Identity::parse_file) {
            keys.extend(ids.into_iter().map(RevealKey::Identity));
            continue;
        }
        // An unprotected key opens without asking.
        let (id, info) = match stegpony_core::pgp::identity_from_pgp(&bytes, "") {
            Ok(found) => found,
            Err(stegpony_core::Error::WrongPassphrase) => {
                let pass = passphrase(
                    "STEGPONY_PGP_PASSPHRASE",
                    &format!("Passphrase for {}", path.display()),
                    false,
                )?;
                stegpony_core::pgp::identity_from_pgp(&bytes, &pass)
                    .with_context(|| format!("reading {}", path.display()))?
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        eprintln!("using OpenPGP subkey {}", info.subkey_fingerprint);
        keys.push(RevealKey::Identity(id));
    }
    if a.passphrase || keys.is_empty() {
        keys.push(RevealKey::Passphrase(passphrase(
            "STEGPONY_PASSPHRASE",
            "Passphrase",
            false,
        )?));
    }
    let found = if image.starts_with(&[0xff, 0xd8, 0xff]) {
        jpeg::reveal(&image, &keys)?
    } else if image.starts_with(b"\x89PNG") {
        lossless::reveal(&image, &keys)?
    } else {
        let t = std::str::from_utf8(&image).context("not a PNG, JPEG or UTF-8 text file")?;
        match text::reveal(t, &keys)? {
            text::TextFound::Payload(p, _) => Some(p),
            text::TextFound::Nothing(_) => None,
        }
    };
    match found {
        None => {
            eprintln!("nothing found");
            std::process::exit(1);
        }
        Some(Payload::Text(t)) => {
            println!("{t}");
        }
        Some(Payload::File { name, data, .. }) => {
            let path = safe_output_path(&a.out_dir, &name)?;
            fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
    }
    Ok(())
}

/// An age1... recipient, or a file holding a Curve25519 OpenPGP key.
fn parse_recipient(s: &str) -> Result<Recipient> {
    if let Ok(r) = Recipient::parse(s) {
        return Ok(r);
    }
    let path = Path::new(s);
    if !path.is_file() {
        bail!("{s} is neither an age1... recipient nor a key file");
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let info = stegpony_core::pgp::recipient_from_pgp(&bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    let who = info.user_ids.first().map_or("", String::as_str);
    eprintln!(
        "hiding for OpenPGP subkey {} {who}",
        info.subkey_fingerprint
    );
    Ok(info.recipient)
}

/// Keeps a revealed file name from escaping the output directory or clobbering a file.
fn safe_output_path(dir: &Path, name: &str) -> Result<PathBuf> {
    let base = Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| "revealed.bin".into());
    let mut path = dir.join(&base);
    let mut i = 1;
    while path.exists() {
        path = dir.join(format!("{i}-{base}"));
        i += 1;
    }
    Ok(path)
}

fn capacity(cover: &Path, mode: ImageMode) -> Result<()> {
    let bytes = fs::read(cover).with_context(|| format!("reading {}", cover.display()))?;
    let c = match mode {
        ImageMode::Lossless => lossless::capacity(&bytes)?,
        ImageMode::Jpeg => jpeg::capacity(&bytes)?,
        ImageMode::Words | ImageMode::ZeroWidth => {
            bail!(
                "text output grows with the payload; the largest is {} bytes of text",
                text::max_text_bytes()
            )
        }
    };
    println!("elements per slot: {} / {}", c.elements[0], c.elements[1]);
    match c.max_bucket {
        Some(_) => println!("largest message: {} bytes of text", c.max_text_bytes),
        None => println!("too small to hold anything"),
    }
    Ok(())
}

fn keygen(output: Option<PathBuf>) -> Result<()> {
    let id = Identity::generate(&mut OsRng);
    let text = Zeroizing::new(format!(
        "# public key: {}\n{}\n",
        id.recipient(),
        id.to_age_string()
    ));
    match output {
        Some(path) => {
            write_private(&path, text.as_bytes())?;
            eprintln!("Public key: {}", id.recipient());
        }
        None => print!("{}", *text),
    }
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    fs::write(path, data)?;
    Ok(())
}
