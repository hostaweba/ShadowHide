# ShadowHide (Cryptosteganography Tool)

## Overview

This is a **Cryptosteganography** tool written in **Python 3** with a modern **PySide6** GUI. It allows you to hide any type of file (images, audio, executables, documents, etc.) inside image carriers using **Least Significant Bit (LSB) steganography**. The tool also supports **encryption, compression, integrity checks, sharding, redundancy, and batch operations**.

The program provides:

* A **user-friendly GUI** built with PySide6.
* A **command-line interface (CLI)** for automation.
* Robust **error handling** with clear and actionable messages.

## Features

* Hide any file type inside images.
* Multiple carriers & batch payload support.
* **Compression, encryption (AES via Fernet), HMAC integrity checks**.
* **Capacity estimator** with smart error handling.
* **Auto-open extracted files** after decoding.
* **Sharding** for splitting large payloads across multiple carriers.
* **Redundancy/replication** to make recovery more reliable.
* Presets and recent-project management for repeat workflows.
* Background workers with progress logs.
* CLI mode for headless/batch usage.

## Technology Stack

* **Python 3.8+**
* **GUI**: PySide6 (Qt)
* **Image processing**: OpenCV (cv2) and Pillow (PIL)
* **Math / data**: NumPy
* **Crypto**: cryptography (PBKDF2HMAC, Fernet, HMAC-SHA256)

## How It Works

### Encoding

1. Select carrier images (PNG recommended) and a payload file.
2. The payload is optionally **compressed** and/or **encrypted**.
3. Metadata is built (filename, size, compression/encryption flags, HMAC, etc.).
4. Data is converted to binary and embedded into the **LSB(s)** of carrier pixels.
5. The output is a **stego image** that looks unchanged but contains hidden data.

### Decoding

1. Load the stego image.
2. Extract binary bits from LSBs.
3. Reconstruct metadata and payload.
4. Verify **HMAC** and decrypt/decompress if required.
5. Output the original file (with auto-open option).

## Installation

### Requirements

* Python 3.8 or higher
* Dependencies:

  ```bash
  pip install PySide6 numpy opencv-python pillow cryptography
  ```
* (Optional) cryptosteganography library:

  ```bash
  pip install cryptosteganography
  ```

### Run

```bash
python main.py
```

## CLI Usage

In addition to the GUI, the program can be run in CLI mode:

```bash
python main.py --encode -c carrier.png -p secret.mp3 -o stego.png --password mypass

python main.py --decode -i stego.png --password mypass
```

Options include:

* `--encode` / `--decode`
* `-c, --carrier` : Carrier image(s)
* `-p, --payload` : Payload file
* `-o, --output` : Output stego image
* `--password` : Password for encryption/decryption
* `--shard` : Split payload across multiple carriers
* `--redundancy` : Add redundancy blocks

## Error Handling

The tool is designed to **fail gracefully** with clear explanations:

* Capacity exceeded → "Payload too large, try larger carrier or enable 2-bit mode."
* Wrong password → "Integrity check failed (wrong key or corrupted data)."
* Unsupported format → "Use lossless formats (PNG recommended)."

## Roadmap

* Add **Reed-Solomon error correction** for noisy/lossy carriers.
* Visual **capacity graphs** in GUI.
* Support for more **advanced key derivation** (Argon2).
* Export/import of entire projects.

## Contributing

1. Fork and clone this repository.
2. Install dependencies.
3. Make changes in a feature branch.
4. Submit a pull request.

Please ensure your contributions:

* Maintain **GUI/backend separation** (use signals, no direct UI calls in backend).
* Follow PEP8 coding style.
* Add docstrings and error handling.

## License

This project is released under the **MIT License**.

---

For a deeper dive into how this code works, see [About\_code.md](About_code.md).
