# About This Program

## Introduction

This project is a **Cryptosteganography** that combines classical steganographic techniques with modern cryptography and error handling. The program is written in **Python 3** and uses **PySide6 (Qt for Python)** to provide a clean, interactive GUI alongside a command-line interface for automation.

## Design Goals

* Hide any type of file (image, audio, video, document, executables) inside an image carrier.
* Provide **robust security** via encryption (AES/Fernet) and integrity checks (HMAC-SHA256).
* Ensure **usability** with a user-friendly PySide6 GUI, batch operations, and drag & drop.
* Handle large files by **sharding across multiple carriers** and adding redundancy for resilience.
* Offer both **GUI mode** for end-users and **CLI mode** for advanced/batch workflows.

## Architecture

The codebase is organized into three main layers:

### 1. Core Steganography Engine

* **Encoding**: Converts payload files into binary streams, adds metadata (filename, size, flags), and embeds bits into carrier image pixels using LSB substitution.
* **Decoding**: Extracts binary from stego images, reconstructs metadata and payload, verifies HMAC, then decrypts/decompresses as needed.
* **Capacity Management**: Estimates maximum payload capacity per carrier, supports 1-bit or 2-bit LSB modes.
* **Sharding & Redundancy**: Splits large payloads across multiple carriers or replicates blocks for fault tolerance.

### 2. Security Layer

* **Encryption**: Uses AES via `cryptography.fernet` with keys derived from user passwords using PBKDF2HMAC.
* **Integrity**: HMAC-SHA256 protects against tampering or incorrect passwords.
* **Compression**: Optional zlib-based compression reduces payload size before embedding.

### 3. User Interface & Workflow

* **PySide6 GUI**: Provides tabs for encoding/decoding, drag & drop support, progress bars, logs, and settings (encryption, compression, redundancy, shards).
* **Signals & Workers**: Long-running encoding/decoding tasks run in worker threads to keep the GUI responsive.
* **Error Handling**: All critical operations are wrapped with descriptive error messages. Examples:

  * Capacity exceeded → “Payload too large for selected carrier(s). Try enabling 2-bit mode or larger carriers.”
  * Wrong password → “Integrity check failed. Possible wrong password or corrupted data.”
  * Unsupported format → “Use lossless images (PNG recommended) for accurate decoding.”
* **CLI Mode**: Mirrors GUI functionality with `--encode` and `--decode` options.

## Metadata Format

Each hidden payload begins with a structured header:

* File name length + file name (UTF-8)
* Payload size (bytes)
* Flags (compression, encryption, redundancy, shard index)
* Integrity HMAC (SHA256)
* Payload data (possibly compressed/encrypted)

This ensures that decoding can validate and reconstruct files reliably.

## Workflow Example

### Encoding

1. User selects `cover.png` and `secret.mp3`.
2. Program compresses `secret.mp3`, encrypts it with password, generates HMAC.
3. Metadata + payload are embedded into the LSBs of `cover.png`.
4. Output: `cover_stego.png` visually identical to the original.

### Decoding

1. User selects `cover_stego.png` and enters password.
2. Program extracts binary data, verifies HMAC, decrypts, and decompresses.
3. Output: `secret.mp3` is restored, identical to original.

## Error Handling Philosophy

* **Prevent**: Capacity estimator blocks impossible operations.
* **Detect**: Integrity checks catch corruption or wrong keys.
* **Explain**: Every error shown in GUI/logs has a clear human-readable explanation.
* **Recover**: Redundancy and sharding increase the chance of recovery even with partial data loss.

## Future Improvements

* Add **Reed-Solomon error correction** for lossy carriers.
* Visual **capacity graphs** in GUI.
* Switch to **Argon2id** for stronger key derivation.
* Embed a **built-in viewer** for common file types (images, text, audio).

---

This program is designed to balance **security, usability, and resilience**, making it a powerful yet user-friendly cryptosteganography tool.
