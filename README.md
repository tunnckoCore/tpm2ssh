# tpm2ssh

> **Hardware-Backed, In-Memory Only SSH & Git Signing Keys.**

`tpm2ssh` is a security-first utility that leverages your computer's **TPM 2.0 (Trusted Platform Module)** to manage SSH keys. Unlike traditional setups where private keys are stored on your SSD (even if encrypted), `tpm2ssh` ensures your private key **never touches the disk**.

## 🧠 Motivation

The primary goal is to achieve a "Stateless Security" model for developer identities:

1.  **Eliminate Disk Forensics:** By deriving the key mathematically in RAM, there is no private key file for an attacker to steal from your filesystem.
2.  **Hardware Binding:** The root secret is "sealed" into the TPM, meaning it cannot be used on any other machine, even if your entire drive is cloned or stolen.
3.  **Unified Identity:** One hardware-backed key for both SSH (GitHub/Server access) and Git Commit Signing.
4.  **Zero-Prompt Workflow:** Seamless integration with standard OpenSSH agents, bypassing the clunky GPG/KWallet or keyrings.

## 🛠 How It Works (The Protocol)

The tool operates on a deterministic derivation pipeline:

1.  **Sealing (Setup Phase):**
    *   A high-entropy 32-byte seed is generated or provided by the user.
    *   The tool discovers a free persistent handle in the TPM module (defaulting to `0x81006969` or user provided).
    *   This seed is "sealed" into the TPM's NVRAM at that handle.
    *   The seal is protected by a user-defined **TPM PIN**.
    *   The handle address is saved to `~/.ssh/tpm2/handle.txt`.
2.  **Unsealing (Login Phase):**
    *   The user provides the TPM PIN.
    *   The TPM verifies the PIN and system integrity, then releases the raw 32-byte seed into RAM.
3.  **Key Derivation:**
    *   The seed is passed through **HKDF-SHA256** (HMAC-based Key Derivation Function) using a secure salt and info string.
    *   This results in a deterministic 256-bit scalar.
4.  **Key Generation:**
    *   The scalar is used as the private key for either an **ECDSA NIST P-256 (secp256r1)** or **Ed25519** curve.
    *   The corresponding public key is calculated.
5.  **Injection:**
    *   The tool formats the result as an OpenSSH Private Key and pipes it directly into the `ssh-agent` memory.
    *   The public key is written to `~/.ssh/tpm2/id_{username}_{alg}_tpm2.pub` for Git compatibility.

## 📋 Requirements

*   **Linux** with a functional TPM 2.0 chip.
*   **Packages:** `tpm2-tools`, `openssh`.
*   **Permissions:** User must be in the `tss` group to access `/dev/tpmrm0`.

## 🚀 Usage

### Initial Setup

Run this once to generate your hardware-bound secret. It will prompt you if you want to import an existing seed or generate a new one, and if you want to display the final seed for backup.

```bash
tpm2ssh --setup
```

### Every Boot (Login)
Run this to unlock your keys into memory. It will prompt you for:
*   Identity username (defaults to your system user).
*   Algorithm (NIST P-256 or Ed25519).
*   Whether to display the private key for backup.
*   Your TPM PIN.

```bash
tpm2ssh --login
```

### Git Integration
Configure Git to use your new hardware key for signing:

```bash
git config --global gpg.format ssh
git config --global user.signingkey "~/.ssh/tpm2/id_{username}_{algo}_tpm2.pub"
git config --global commit.gpgsign true
```

## 🔐 Recovery & FAQ

### What is PIN, and can it be anything?

The TPM **PIN can be anything** - phrase, password, PIN digits, whatever. It is used to "seal" (like encrypt) the final seed that is stored at the TPM handle. The PIN itself is not used directly for derivation of anything - for that cryptographic secrets and primitives are used.

### Why should I backup the seed?

The **32-byte master seed** is the ultimate root of your identity. If you have this seed, you can recreate your SSH and Git signing keys on **any** machine, regardless of the TPM.

### How to backup?

*   **Seed Backup:** During `tpm2ssh --setup`, choose **"y"** when asked to show the final seed. Store this hex string in a secure, encrypted password manager.
*   **Private Key Backup:** When running `tpm2ssh --login`, choose **"y"** when asked to show the private key.

### How to restore?

*   **New TPM/Laptop:** Run `tpm2ssh --setup` and provide your backed-up hex seed when prompted. This will seal the *same* seed into your new hardware, ensuring your public keys remain exactly the same.
*   **Manual Restore:** If you don't have a TPM available, you can use the backed-up private key string directly with `ssh-add -`.

### What happens if I reinstall my OS?

As long as the TPM hasn't been cleared, your seed is still safe in its hardware slot. Simply reinstall the requirements, ensure `~/.ssh/tpm2/handle.txt` contains the correct hex handle (or let the tool rediscover it if you remember the range), and run `tpm2ssh --login`. No "restoration" of the seed is needed - it's already in the hardware.

### More about the security of pieces

#### The "TPM handle" is just an "Address"

A TPM handle is like a filename or a memory address. Knowing that your seed is at `0x81006969` is exactly the same as an attacker knowing your private key is at `~/.ssh/id_ed25519`. They can see the file exists, but they cannot read its contents.

#### Why Root/Sudo Access isn't enough

Even if an attacker has remote root access, they still face the Hardware Gatekeeper:

*   **The PIN Requirement:** To "unseal" the data at that handle, the attacker must provide the correct PIN. This PIN is processed inside the TPM chip.
*   **No "Dump" Command:** There is no command in the TPM protocol to "dump memory" or bypass the authorization check. The TPM is designed to be a "black box" that only releases data when the cryptographic conditions are met.

#### Native Protection Against Brute Force (Dictionary Attacks)

You might worry that an attacker with the handle could just keep guessing the PIN.

*   **TPM Lockout:** All modern TPM 2.0 chips have built-in Dictionary Attack Protection. If someone tries the wrong PIN a few times (usually 3–10), the TPM will lock itself for a period of time (or until a physical reboot/cooldown). 
*   **Hardware Speed:** Because the PIN is checked inside the hardware, an attacker can't use their powerful GPU or CPU to guess millions of PINs per second. They are limited by the physical speed of the TPM chip, which is intentionally slow.
