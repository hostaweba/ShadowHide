# Help Guide

This document explains how to use the **Cryptosteganography** in detail. It covers the GUI tabs, buttons, inputs, CLI mode, and different usage combinations for best results.

---

## Getting Started

1. Launch the program.
2. Choose whether to work in **Encode** (hide a file) or **Decode** (extract a file).
3. Follow on-screen instructions depending on the tab selected, or run from the command line in **CLI mode**.

---

## GUI Layout

The main interface is divided into multiple **tabs**:

### 1. Encode Tab

Use this tab to hide a file inside an image.

**Inputs:**

* **Carrier Image**: Select a PNG (preferred), BMP, or other lossless image.
* **Payload File**: Select any file (image, audio, video, text, document, executable, etc.).
* **Password (optional)**: Enables encryption of the payload.
* **Compression Toggle**: Reduces size before embedding.
* **Redundancy / Sharding Options**: Split or duplicate payload across multiple carriers.
* **Save As**: Path for the stego image.

**Buttons:**

* **Browse…**: Select files and save location.
* **Encode**: Start embedding process.
* **Clear**: Reset inputs.

**Best Use Tips:**

* PNG carriers work best (lossless, high capacity).
* Use compression for large text/audio files.
* Enable encryption + HMAC when hiding sensitive files.
* Use sharding if file is larger than one image’s capacity.

### 2. Decode Tab

Use this tab to extract hidden files from a stego image.

**Inputs:**

* **Stego Image**: The image containing hidden data.
* **Password (if required)**: Needed if payload was encrypted.
* **Save Location**: Destination folder for extracted file.

**Buttons:**

* **Browse…**: Select stego image and output folder.
* **Decode**: Start extraction.
* **Auto-Open File**: Open result with system default application.

**Results & Errors:**

* Correct password → payload is restored.
* Wrong password → “Integrity check failed” error.
* Wrong image → “No payload found” error.
* Corrupted image → descriptive error message.

### 3. Batch Tab

For hiding/extracting multiple files.

* Drag and drop multiple payloads and carriers.
* Supports sharding large payloads into many carriers.
* Status column shows success or errors for each file.

### 4. Settings Tab

Fine-tune advanced options.

* **LSB Depth**: Use 1 or 2 bits per pixel (higher = more capacity, lower = more safety).
* **Redundancy Factor**: Number of duplicate blocks for fault tolerance.
* **Logs**: Toggle detailed logs.
* **Default Save Folder**: Configure default output path.

---

## CLI Mode (Command Line Interface)

The tool also supports command-line usage for scripting, automation, and advanced users.

### Basic Syntax

```bash
cryptosteg encode -c <carrier.png> -p <payload.ext> -o <stego.png> [options]
cryptosteg decode -s <stego.png> -o <output_folder> [options]
```

### Options

* `-c, --carrier` : Carrier image (PNG recommended).
* `-p, --payload` : File to hide.
* `-s, --stego` : Stego image to decode.
* `-o, --output` : Output file or folder.
* `-pw, --password` : Password for encryption/decryption.
* `--compress` : Enable compression before embedding.
* `--redundancy N` : Set redundancy factor (default: 1).
* `--shard` : Enable file sharding across multiple carriers.
* `--depth N` : LSB depth (1 or 2).
* `--auto-open` : Auto-open extracted file after decoding.
* `-v, --verbose` : Show detailed logs.

### Examples

**1. Simple Encode:**

```bash
cryptosteg encode -c cover.png -p secret.txt -o cover_stego.png
```

**2. Encode with Password & Compression:**

```bash
cryptosteg encode -c cover.png -p secret.pdf -o cover_secure.png -pw mypass --compress
```

**3. Shard Large File Across Multiple Images:**

```bash
cryptosteg encode -c cover1.png cover2.png cover3.png -p movie.mp4 -o stego_ --shard
```

*(creates stego\_1.png, stego\_2.png, stego\_3.png)*

**4. Decode with Password:**

```bash
cryptosteg decode -s cover_secure.png -o ./output -pw mypass
```

**5. Batch Decode All Stego Images in Folder:**

```bash
cryptosteg decode -s ./stego_folder/*.png -o ./decoded
```

---

## Example Workflows

### Simple Encoding

* Carrier: `cover.png`
* Payload: `secret.txt`
* No encryption, no compression → `cover_stego.png`
* Decode with no password → restores `secret.txt`

### Secure Encoding

* Carrier: `cover.png`
* Payload: `secret.pdf`
* Enable compression + encryption with password “mypassword”
* Decode requires password → restores `secret.pdf`

### Large File Handling

* Carrier set: `cover1.png`, `cover2.png`, `cover3.png`
* Payload: `movie.mp4`
* Enable **sharding** → payload is split across three carriers.
* All carriers required for successful decode.

### Redundant Encoding

* Carrier: `cover.png`
* Payload: `important.docx`
* Enable **redundancy factor = 3** → same file encoded in multiple blocks.
* Decoding works even if parts of the carrier are corrupted.

---

## Common Errors & Solutions

* **“Payload too large”** → Use bigger carrier, enable compression, or use sharding.
* **“Integrity check failed”** → Wrong password or corrupted stego file.
* **“Unsupported format”** → Use lossless images like PNG instead of JPEG.
* **“Decoding error”** → File may be incomplete; try redundancy or alternative carrier copy.

---

## Best Practices

* Always prefer **PNG** carriers.
* Use **password + HMAC** for sensitive files.
* Keep a backup of original payload before encoding.
* For critical files, combine **compression + encryption + redundancy**.
* Avoid editing or re-saving stego images in lossy formats (JPEG) after encoding.

---

This guide should help you make full use of the tool’s features (GUI and CLI) and understand the effects of different settings for safe, efficient cryptosteganography.
