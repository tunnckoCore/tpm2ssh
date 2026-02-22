use hkdf::Hkdf;
use p256::SecretKey;
use rpassword::prompt_password;
use sha2::Sha256;
use ssh_key::{private::EcdsaKeypair, private::Ed25519Keypair, private::KeypairData, PrivateKey};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};

const DEFAULT_HANDLE: &str = "0x81006969";

fn get_stdio(verbose: bool) -> Stdio {
    if verbose {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

fn prompt(question: &str, default: &str) -> String {
    print!("{} [{}]: ", question, default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn get_persistent_handles() -> Vec<String> {
    let output = Command::new("tpm2_getcap")
        .args(&["handles-persistent"])
        .output()
        .expect("Failed to run tpm2_getcap");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("- ") {
                Some(trimmed[2..].to_string())
            } else if trimmed.starts_with("0x") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn find_first_free_handle(taken: &[String]) -> String {
    for i in 0x0000..=0xFFFF {
        let handle = format!("0x8100{:04x}", i);
        if !taken.contains(&handle) {
            return handle;
        }
    }
    // Fallback to something if everything is taken (unlikely)
    "0x8100ffff".to_string()
}

fn setup(verbose: bool) {
    let home = env::var("HOME").expect("HOME not set");
    let tpm2ssh_dir = format!("{}/.ssh/tpm2ssh", home);
    let temp_tpm2ssh_dir = format!("/tmp/tpm2ssh-temp");
    fs::create_dir_all(&tpm2ssh_dir).unwrap();
    fs::create_dir_all(&temp_tpm2ssh_dir).unwrap();

    let pin = prompt_password("Enter new TPM PIN: ").unwrap();
    let pin_confirm = prompt_password("Confirm TPM PIN: ").unwrap();
    if pin != pin_confirm {
        eprintln!("PINs do not match.");
        std::process::exit(1);
    }

    let seed_hex = prompt(
        "Provide 32-byte hex seed to import? (Leave empty for new)",
        "",
    );
    let seed_bytes = if !seed_hex.is_empty() {
        match hex::decode(seed_hex.trim()) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    eprintln!("Error: Seed must be exactly 32 bytes (64 hex characters).");
                    std::process::exit(1);
                }
                bytes
            }
            Err(e) => {
                eprintln!("Error decoding hex seed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("Generating secure seed...");
        let output = Command::new("tpm2_getrandom")
            .args(&["32"])
            .output()
            .unwrap();
        if !output.status.success() {
            eprintln!("Failed to generate random seed from TPM.");
            std::process::exit(1);
        }
        output.stdout
    };

    let show_seed = prompt("Show final seed for backup? (y/n)", "n").to_lowercase() == "y";
    if show_seed {
        println!("---- SEED BACKUP (HEX) ----");
        println!("{}", hex::encode(&seed_bytes));
        println!("---------------------------");
    }

    let seed_path = format!("{}/seed.dat", temp_tpm2ssh_dir);
    fs::write(&seed_path, &seed_bytes).unwrap();

    println!("Discovering free TPM handle...");
    let taken = get_persistent_handles();
    let chosen_handle = if taken.contains(&DEFAULT_HANDLE.to_string()) {
        let suggested = find_first_free_handle(&taken);
        prompt(
            &format!("Default handle {} is busy. Use suggested?", DEFAULT_HANDLE),
            &suggested,
        )
    } else {
        DEFAULT_HANDLE.to_string()
    };

    println!("Creating primary context...");
    Command::new("tpm2_createprimary")
        .args(&["-c", &format!("{}/primary.ctx", temp_tpm2ssh_dir)])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Sealing seed into TPM...");
    Command::new("tpm2_create")
        .args(&[
            "-C",
            &format!("{}/primary.ctx", temp_tpm2ssh_dir),
            "-p",
            &pin,
            "-i",
            &seed_path,
            "-u",
            &format!("{}/seal.pub", temp_tpm2ssh_dir),
            "-r",
            &format!("{}/seal.priv", temp_tpm2ssh_dir),
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Loading sealed object...");
    Command::new("tpm2_load")
        .args(&[
            "-C",
            &format!("{}/primary.ctx", temp_tpm2ssh_dir),
            "-u",
            &format!("{}/seal.pub", temp_tpm2ssh_dir),
            "-r",
            &format!("{}/seal.priv", temp_tpm2ssh_dir),
            "-c",
            &format!("{}/seal.ctx", temp_tpm2ssh_dir),
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    println!("Making it persistent at handle {}...", chosen_handle);
    let status = Command::new("tpm2_evictcontrol")
        .args(&[
            "-C",
            "o",
            "-c",
            &format!("{}/seal.ctx", temp_tpm2ssh_dir),
            &chosen_handle,
        ])
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .status()
        .unwrap();

    if status.success() {
        println!("TPM Setup complete! Handle saved to handle.txt.");
        fs::write(format!("{}/handle.txt", tpm2ssh_dir), &chosen_handle).unwrap();
        // Clean up
        let _ = fs::remove_file(&seed_path);
        let _ = fs::remove_file(format!("{}/primary.ctx", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.ctx", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.priv", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.pub", temp_tpm2ssh_dir));
    } else {
        let _ = fs::remove_file(format!("{}/primary.ctx", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.ctx", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.priv", temp_tpm2ssh_dir));
        let _ = fs::remove_file(format!("{}/seal.pub", temp_tpm2ssh_dir));
        eprintln!(
            "Failed to make object persistent. Cleaned the temp dir {}",
            temp_tpm2ssh_dir
        );
        std::process::exit(1);
    }
}

fn login(verbose: bool) {
    let home = env::var("HOME").expect("HOME not set");
    let tpm2ssh_dir = format!("{}/.ssh/tpm2ssh", home);
    let handle_filepath = format!("{}/handle.txt", tpm2ssh_dir);

    let handle = fs::read_to_string(&handle_filepath).unwrap_or(DEFAULT_HANDLE.to_string());
    let username = prompt("Identity username", &whoami::username().unwrap());

    println!("Choose algorithm:");
    println!("1: NIST P-256 (nistp256r1, p256, passkey)");
    println!("2: Ed25519 (ed, ed25519)");
    let alg_choice = prompt("Algorithm", "1");

    let show_priv = prompt("Show private key for backup? (y/n)", "n").to_lowercase() == "y";

    let seed = {
        let pin = match prompt_password("Enter TPM PIN: ") {
            Ok(p) => p,
            Err(_) => std::process::exit(1),
        };

        let output = Command::new("tpm2_unseal")
            .args(&["-c", handle.trim(), "-p", &pin])
            .stderr(get_stdio(verbose))
            .output()
            .unwrap();

        if !output.status.success() {
            eprintln!("Failed to unseal. Wrong PIN, wrong handle, or TPM error.");
            std::process::exit(1);
        }
        output.stdout
    };

    let hkdf = Hkdf::<Sha256>::new(Some(&b"tpm2ssh-v1-based-keys"[..]), &seed);
    let mut expanded_key_material = [0u8; 32];
    hkdf.expand(b"tpm2ssh-hkdf-info", &mut expanded_key_material)
        .unwrap();

    let (keypair_data, alg_name, comment) = if ["2", "ed", "ed25519"].contains(&alg_choice.as_str())
    {
        let ed25519_keypair = Ed25519Keypair::from_seed(&expanded_key_material);
        (
            KeypairData::from(ed25519_keypair),
            "ed25519",
            "tpm2ssh-ed25519-derived-key",
        )
    } else {
        let secret_key = SecretKey::from_slice(&expanded_key_material).unwrap();
        let public_key_ec = secret_key.public_key();
        let ecdsa_keypair = EcdsaKeypair::NistP256 {
            private: secret_key.into(),
            public: public_key_ec.into(),
        };
        (
            KeypairData::from(ecdsa_keypair),
            "nistp256",
            "tpm2ssh-nistp256-derived-key",
        )
    };

    let private_key = PrivateKey::new(keypair_data, comment).unwrap();
    let openssh_pem = private_key.to_openssh(ssh_key::LineEnding::LF).unwrap();

    // Write public key to file
    let pub_key_filename = format!("id_{}_{}_tpm2.pub", username, alg_name);
    let pub_key_path = format!("{}/{}", tpm2ssh_dir, pub_key_filename);
    let pub_key_exists = std::path::Path::new(&pub_key_path).exists();

    let public_key = private_key.public_key();
    let mut public_key_ssh = public_key.to_openssh().unwrap();
    if !public_key_ssh.ends_with('\n') {
        public_key_ssh.push('\n');
    }
    fs::write(&pub_key_path, public_key_ssh).expect("Failed to write public key file");

    if show_priv {
        println!("");
        println!("{}", openssh_pem.to_string());
    }

    // Pipe it into ssh-add
    let socket = format!("/run/user/{}/ssh-agent.socket", unsafe { libc::getuid() });

    let mut child = Command::new("ssh-add")
        .args(&["-q", "-"])
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(Stdio::piped())
        .stdout(get_stdio(verbose))
        .stderr(get_stdio(verbose))
        .spawn()
        .expect("Failed to spawn ssh-add");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(openssh_pem.as_bytes()).unwrap();
    }

    let status = child.wait().unwrap();
    if status.success() {
        if pub_key_exists {
            println!("Key successfully re-added to ssh-agent!");
            println!("Public key already exists at: {}", pub_key_path);
        } else {
            println!("Key successfully added to ssh-agent!");
            println!("Public key written to: {}", pub_key_path);
        }
        println!("\nTo use this agent in your shell, ensure SSH_AUTH_SOCK is set:");
        println!("export SSH_AUTH_SOCK={}", socket);
    } else {
        eprintln!("ssh-add failed.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let verbose = args.iter().any(|arg| arg == "--verbose" || arg == "-v");

    if args.contains(&"--setup".to_string()) {
        setup(verbose);
    } else if args.contains(&"--login".to_string()) {
        login(verbose);
    } else {
        println!("Usage: tpm2ssh [--setup | --login] [-v | --verbose]");
    }
}
