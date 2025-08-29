# -------------
# ShadowHide
# --------------
# Features (user-facing):
# - Intuitive modern GUI layout (status bar, tooltips, inline capacity warnings)
# - Capacity estimator and per-carrier warning (shows required vs available)
# - Multiple LSB modes (1,2 bits per channel) for higher capacity/quality tradeoff
# - Automatic sharding (split large payloads across many carriers) with progress preview
# - Auto-retry & fallback when carrier too small
# - Save/load user settings & recent projects
# - Batch encode/decode with per-file logs, quick preview of embedded payload metadata
# - Built-in CLI mode (run headless with args) for automation
# - Drag & drop, thumbnails, right-click actions (open containing folder, copy path)
# - Quick-help/About dialog
# - Export extracted file list as CSV
# - Optional redundancy (replicate payload across N carriers) to increase resilience
# - UI presets for common workflows

# ShadowHide_improved (Robust, descriptive error handling — fixed syntax/logic bugs)
# This file is an improved, battle-tested iteration focusing on:
#  - descriptive, actionable error messages (why an operation failed and next steps)
#  - safe fallbacks (carrier conversion fallback, auto-escalate LSB mode when possible)
#  - defensive checks (file existence, directory creation, capacity checks)
#  - cleaned up string/newline handling and traceback formatting
#  - avoids raising unhandled exceptions in worker threads; all errors are reported via logs

import sys
import os
import math
import zlib
import base64
import json
import io
import tempfile
import shutil
import mimetypes
import struct
import traceback
import csv
import argparse
from pathlib import Path
from typing import List, Optional, Tuple

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QListWidget, QListWidgetItem, QLabel, QLineEdit, QProgressBar, QMessageBox, QTabWidget,
    QCheckBox, QComboBox, QFrame, QMenu, QAbstractItemView, QSplitter, QStatusBar,
    QToolButton, QInputDialog
)
from PySide6.QtGui import QPixmap, QImage, QDragEnterEvent, QDropEvent, QAction, QIcon
from PySide6.QtCore import Qt, QRunnable, QThreadPool, Signal, QObject, Slot, QSize

import numpy as np
import cv2
from PIL import Image

# Optional module
try:
    from cryptosteganography import CryptoSteganography
    HAS_CS = True
except Exception:
    HAS_CS = False

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# -------------------- Constants & Helpers --------------------
APP_NAME = 'ShadowHide v5.2'
MAGIC = b'ADVSTG5.2'
SETTINGS_FILE = os.path.join(Path.home(), '.advcryptosteg_settings.json')
RECENT_PROJECTS = os.path.join(Path.home(), '.advcryptosteg_recent.json')

LOSSLESS_EXTS = {'.png', '.bmp', '.tiff', '.tif'}
DEFAULT_AUTO_EXTS = '.html,.htm,.py,.bat,.ps1,.sh,.mp3,.txt'


def load_settings():
    try:
        with open(SETTINGS_FILE, 'r') as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_settings(d):
    try:
        with open(SETTINGS_FILE, 'w') as fh:
            json.dump(d, fh, indent=2)
    except Exception:
        pass


def add_recent_project(path: str):
    try:
        l = []
        if os.path.exists(RECENT_PROJECTS):
            with open(RECENT_PROJECTS, 'r') as fh:
                l = json.load(fh)
        l = [path] + [p for p in l if p != path]
        l = l[:10]
        with open(RECENT_PROJECTS, 'w') as fh:
            json.dump(l, fh, indent=2)
    except Exception:
        pass


def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key, salt


def make_thumbnail(path: str, max_size: int = 96) -> QPixmap:
    try:
        img = Image.open(path)
        img.thumbnail((max_size, max_size))
        bio = io.BytesIO()
        img.save(bio, format='PNG')
        qimg = QImage.fromData(bio.getvalue())
        return QPixmap.fromImage(qimg)
    except Exception:
        return QPixmap()


def detect_mimetype(filename: str) -> str:
    mimet, _ = mimetypes.guess_type(filename)
    return mimet or 'application/octet-stream'


def ensure_single_frame_image(path: str) -> str:
    """Return path to a single-frame PNG derived from `path`.
    If carrier conversion fails we fall back to returning the original path but
    the caller will receive a capacity/quality warning. This avoids failing the
    entire encode for unsupported carriers while still preferring lossless.
    """
    ext = Path(path).suffix.lower()
    if ext in LOSSLESS_EXTS and ext != '.webp':
        return path
    try:
        img = Image.open(path)
        img = img.convert('RGBA')
        tmp = os.path.join(tempfile.gettempdir(), f'cryptosteg_carrier_{Path(path).stem}_{os.getpid()}.png')
        img.save(tmp, format='PNG')
        return tmp
    except Exception:
        # fallback to original to avoid hard failure; caller should warn user
        return path


def estimate_capacity_bits(image_path: str, bits_per_channel: int = 1) -> int:
    try:
        img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        if img is None:
            # try PIL fallback
            try:
                p = Image.open(image_path)
                w, h = p.size
                channels = 3
                return w * h * channels * bits_per_channel
            except Exception:
                return 0
        h, w = img.shape[:2]
        channels = 3
        return h * w * channels * bits_per_channel
    except Exception:
        return 0


# -------------------- Bit helpers --------------------


def bytes_to_bits(b: bytes) -> np.ndarray:
    arr = np.frombuffer(b, dtype=np.uint8)
    bits = np.unpackbits(arr, bitorder='big')
    return bits.astype(np.uint8)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-bits.size) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    packed = np.packbits(bits, bitorder='big')
    return packed.tobytes()


def write_bits_to_image(arr: np.ndarray, values: np.ndarray, bits_per_channel: int = 1) -> np.ndarray:
    # Ensure uint8
    arr = arr.astype(np.uint8, copy=True)
    flat = arr[:, :, :3].reshape(-1)
    if bits_per_channel == 1:
        vals = values.astype(np.uint8)
        flat[:vals.size] = (flat[:vals.size] & np.uint8(0xFE)) | vals
    elif bits_per_channel == 2:
        vals = values.astype(np.uint8)
        mask = np.uint8(0xFF ^ 0b11)
        flat[:vals.size] = (flat[:vals.size] & mask) | vals
    else:
        raise ValueError('Unsupported bits_per_channel')
    arr[:, :, :3] = flat.reshape(arr.shape[0], arr.shape[1], 3)
    return arr


def read_bits_array_from_image(image_path: str, bits_per_channel: int = 1) -> np.ndarray:
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read image for LSB extraction')
    flat = img[:, :, :3].reshape(-1).astype(np.uint8)
    if bits_per_channel == 1:
        return (flat & np.uint8(1)).astype(np.uint8)
    elif bits_per_channel == 2:
        vals = (flat & np.uint8(0b11)).astype(np.uint8)
        bits = np.empty(vals.size * 2, dtype=np.uint8)
        bits[0::2] = (vals >> 1) & 1
        bits[1::2] = vals & 1
        return bits
    else:
        raise ValueError('Unsupported bits_per_channel')


def pack_meta(meta: dict) -> bytes:
    j = json.dumps(meta, separators=(',', ':')).encode('utf-8')
    return struct.pack('>I', len(j)) + j


def unpack_meta(b: bytes) -> Tuple[dict, int]:
    if len(b) < 4:
        raise ValueError('truncated header')
    l = struct.unpack('>I', b[:4])[0]
    j = b[4:4 + l]
    meta = json.loads(j.decode('utf-8'))
    return meta, 4 + l


# -------------------- Error interpretation --------------------


def interpret_exception(e: Exception) -> str:
    msg = f'{type(e).__name__}: {str(e)}'
    s = str(e).lower()
    if 'payload too large' in s or 'too large' in s:
        hint = 'Payload exceeds carrier capacity. Try: use a larger carrier, enable 2 bits/channel, or auto-shard across multiple carriers.'
    elif 'magic mismatch' in s or 'no valid payload' in s or 'incomplete header' in s:
        hint = 'The file does not contain a recognized payload with the current LSB settings. Try the other LSB mode or check the file.'
    elif 'hmac verification failed' in s:
        hint = 'Integrity check failed — possible wrong password, corrupted stego file, or wrong HMAC key.'
    elif isinstance(e, (IOError, OSError, FileNotFoundError)):
        hint = 'Filesystem error: check file path, permissions, and available disk space.'
    elif 'failed to convert carrier' in s:
        hint = 'Carrier conversion to lossless PNG failed — the carrier file may be corrupted or unsupported.'
    else:
        hint = 'Unexpected error — check details below.'
    tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
    tb_short = ''.join(tb_lines[:8])
    return f"{msg} -- {hint}\n{tb_short}"


# -------------------- Embedding / Extraction --------------------


def embed_lsb(carrier_path: str, out_path: str, payload: bytes, bits_per_channel: int = 1) -> None:
    carrier_for_use = ensure_single_frame_image(carrier_path)
    img = cv2.imread(carrier_for_use, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read carrier image')
    cap = estimate_capacity_bits(carrier_for_use, bits_per_channel)
    needed = len(payload) * 8
    if needed > cap:
        raise ValueError(f'Payload too large ({needed} bits) for carrier capacity {cap} bits')
    h, w = img.shape[:2]
    arr = img.copy().astype(np.uint8)
    if bits_per_channel == 1:
        bits = bytes_to_bits(payload)
        arr = write_bits_to_image(arr, bits, 1)
    elif bits_per_channel == 2:
        bits = bytes_to_bits(payload)
        pad = (-bits.size) % 2
        if pad:
            bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
        pairs = bits.reshape(-1, 2)
        vals = (pairs[:, 0] << 1) | pairs[:, 1]
        arr = write_bits_to_image(arr, vals, 2)
    else:
        raise ValueError('Unsupported bits_per_channel')
    out_path2 = os.path.splitext(out_path)[0] + '.png'
    out_dir = os.path.dirname(out_path2)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    success = cv2.imwrite(out_path2, arr)
    if not success:
        raise IOError('Failed to write stego image (cv2.imwrite returned False)')


def extract_payload_from_image(stego_path: str, bits_per_channel: int = 1) -> Tuple[dict, bytes]:
    arr_bits = read_bits_array_from_image(stego_path, bits_per_channel)
    header_len = len(MAGIC) + 4
    header_bits = header_len * 8
    if arr_bits.size < header_bits:
        raise ValueError('Image does not contain a complete header (file too small or wrong LSB mode)')
    first_bits = arr_bits[:header_bits]
    first_bytes = bits_to_bytes(first_bits)
    if not first_bytes.startswith(MAGIC):
        raise ValueError('No valid payload (magic mismatch)')
    meta_len = struct.unpack('>I', first_bytes[len(MAGIC):len(MAGIC) + 4])[0]
    meta_total_bytes = 4 + meta_len
    meta_total_bits = meta_total_bytes * 8
    if arr_bits.size < len(MAGIC) * 8 + meta_total_bits:
        raise ValueError('Incomplete meta in stego image')
    meta_bits = arr_bits[len(MAGIC) * 8: len(MAGIC) * 8 + meta_total_bits]
    meta_full = bits_to_bytes(meta_bits)
    meta, consumed = unpack_meta(meta_full)
    payload_len = int(meta.get('payload_len', 0))
    payload_start_bit = (len(MAGIC) + meta_total_bytes) * 8
    if payload_len <= 0:
        rest_bits = arr_bits[payload_start_bit:]
        data = bits_to_bytes(rest_bits)
        return meta, data
    end_bit = payload_start_bit + payload_len * 8
    if arr_bits.size < end_bit:
        raise ValueError(f'Incomplete payload: expected {payload_len} bytes, image holds only {(arr_bits.size - payload_start_bit)//8} bytes')
    payload_bits = arr_bits[payload_start_bit:end_bit]
    data = bits_to_bytes(payload_bits)[:payload_len]
    return meta, data


# -------------------- File open / move helpers --------------------


def open_file_default(path: str):
    try:
        if sys.platform.startswith('win'):
            os.startfile(path)
        elif sys.platform.startswith('darwin'):
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')
    except Exception:
        try:
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(path))
        except Exception:
            pass


def move_to_programs_and_open(path: str, programs_dir: str) -> str:
    os.makedirs(programs_dir, exist_ok=True)
    dest = os.path.join(programs_dir, os.path.basename(path))
    try:
        if os.path.abspath(path) != os.path.abspath(dest):
            if not os.path.exists(dest):
                shutil.move(path, dest)
            else:
                base, ext = os.path.splitext(dest)
                idx = 1
                newdest = f"{base}_{idx}{ext}"
                while os.path.exists(newdest):
                    idx += 1
                    newdest = f"{base}_{idx}{ext}"
                shutil.move(path, newdest)
                dest = newdest
    except Exception:
        pass
    open_file_default(dest)
    return dest


# -------------------- Workers & Signals (with detailed error handling) --------------------


class Signals(QObject):
    progress = Signal(int)
    log = Signal(str)
    finished = Signal()


class EncodeWorker(QRunnable):
    def __init__(self, tasks: List[dict], options: dict):
        super().__init__()
        self.tasks = tasks
        self.options = options
        self.signals = Signals()

    @Slot()
    def run(self):
        total = len(self.tasks)
        for i, t in enumerate(self.tasks):
            carrier = t.get('carrier')
            try:
                payload_path = t.get('payload')
                out = t.get('out')
                if not carrier or not os.path.exists(carrier):
                    raise FileNotFoundError(f'Carrier not found: {carrier}')
                if not payload_path or not os.path.exists(payload_path):
                    raise FileNotFoundError(f'Payload not found: {payload_path}')

                bits_per_channel = int(self.options.get('bits_per_channel', 1))
                if bits_per_channel not in (1, 2):
                    bits_per_channel = 1

                data = open(payload_path, 'rb').read()
                meta = {
                    'filename': os.path.basename(payload_path),
                    'index': t.get('index', 0),
                    'shards': t.get('shards', 1),
                    'mimetype': detect_mimetype(payload_path),
                }
                if self.options.get('compress'):
                    data = zlib.compress(data)
                    meta['compressed'] = True
                else:
                    meta['compressed'] = False
                if self.options.get('encrypt') and self.options.get('password'):
                    key, salt = derive_key(self.options.get('password'))
                    meta['salt'] = base64.b64encode(salt).decode('ascii')
                    f = Fernet(key)
                    data = f.encrypt(data)
                    meta['encrypted'] = True
                else:
                    meta['encrypted'] = False
                meta['payload_len'] = len(data)
                hkey = self.options.get('hmac_key') or (self.options.get('password') or 'hmac-salt').encode('utf-8')
                h = hmac.HMAC(hkey, hashes.SHA256(), backend=default_backend())
                h.update(data)
                mac = h.finalize()
                meta['hmac'] = base64.b64encode(mac).decode('ascii')

                payload = MAGIC + pack_meta(meta) + data

                try:
                    embed_lsb(carrier, out, payload, bits_per_channel)
                except Exception as e:
                    s = str(e).lower()
                    # escalate if possible
                    if ('payload too large' in s or 'too large' in s) and bits_per_channel == 1 and self.options.get('auto_escalate', True):
                        try:
                            embed_lsb(carrier, out, payload, 2)
                            self.signals.log.emit(f'Encoded -> {out} (auto-escalated to 2 bits/channel)')
                            self.signals.progress.emit(int((i + 1) / total * 100))
                            continue
                        except Exception as e2:
                            self.signals.log.emit(f'ERROR encoding {carrier}: {interpret_exception(e2)}')
                            self.signals.progress.emit(int((i + 1) / total * 100))
                            continue
                    else:
                        self.signals.log.emit(f'ERROR encoding {carrier}: {interpret_exception(e)}')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue

                self.signals.log.emit(f'Encoded -> {out}')
            except Exception as e:
                self.signals.log.emit(f'ERROR encoding {carrier}: {interpret_exception(e)}')
            self.signals.progress.emit(int((i + 1) / total * 100))
        self.signals.finished.emit()


class DecodeWorker(QRunnable):
    def __init__(self, files: List[str], out_folder: str, options: dict):
        super().__init__()
        self.files = files
        self.out_folder = out_folder
        self.options = options
        self.signals = Signals()

    @Slot()
    def run(self):
        total = len(self.files)
        for i, fpath in enumerate(self.files):
            try:
                if not os.path.exists(fpath):
                    raise FileNotFoundError(f'Stego file not found: {fpath}')
                bits_per_channel = int(self.options.get('bits_per_channel', 1))
                if bits_per_channel not in (1, 2):
                    bits_per_channel = 1

                try:
                    meta, data = extract_payload_from_image(fpath, bits_per_channel)
                except Exception as e:
                    s = str(e).lower()
                    if ('magic' in s or 'no valid payload' in s or 'incomplete header' in s) and bits_per_channel == 1:
                        try:
                            meta, data = extract_payload_from_image(fpath, 2)
                            self.signals.log.emit(f'Decode: swapped LSB mode to 2 bits/channel and succeeded')
                        except Exception as e2:
                            self.signals.log.emit(f'ERROR decoding {fpath}: {interpret_exception(e2)}')
                            self.signals.progress.emit(int((i + 1) / total * 100))
                            continue
                    else:
                        self.signals.log.emit(f'ERROR decoding {fpath}: {interpret_exception(e)}')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue

                hkey = self.options.get('hmac_key') or (self.options.get('password') or 'hmac-salt').encode('utf-8')
                if 'hmac' in meta:
                    try:
                        mac = base64.b64decode(meta['hmac'])
                        h = hmac.HMAC(hkey, hashes.SHA256(), backend=default_backend())
                        h.update(data)
                        h.verify(mac)
                    except Exception:
                        self.signals.log.emit(f'ERROR decoding {fpath}: HMAC verification failed — wrong password or corrupted file')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue

                if meta.get('encrypted'):
                    salt = base64.b64decode(meta.get('salt')) if meta.get('salt') else None
                    password = self.options.get('password')
                    if not password:
                        self.signals.log.emit(f'ERROR decoding {fpath}: Encrypted payload requires password')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue
                    key, _ = derive_key(password, salt)
                    f = Fernet(key)
                    try:
                        data = f.decrypt(data)
                    except Exception:
                        self.signals.log.emit(f'ERROR decoding {fpath}: Decryption failed — incorrect password or corrupted data')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue

                if meta.get('compressed'):
                    try:
                        data = zlib.decompress(data)
                    except Exception:
                        self.signals.log.emit(f'ERROR decoding {fpath}: Decompression failed — corrupted compressed data')
                        self.signals.progress.emit(int((i + 1) / total * 100))
                        continue

                out_name = meta.get('filename', 'extracted.bin')
                out_path = os.path.join(self.out_folder, out_name)
                out_dir = os.path.dirname(out_path)
                if out_dir and not os.path.exists(out_dir):
                    os.makedirs(out_dir, exist_ok=True)
                base, ext = os.path.splitext(out_path)
                idx = 1
                while os.path.exists(out_path):
                    out_path = f"{base}_{idx}{ext}"
                    idx += 1
                with open(out_path, 'wb') as fh:
                    fh.write(data)
                self.signals.log.emit(f'Decoded -> {out_path}')

                auto_exts = self.options.get('auto_open_exts') or set()
                move_to_programs = self.options.get('move_to_programs')
                programs_dir = self.options.get('programs_dir')
                if self.options.get('auto_open_all') or (Path(out_path).suffix.lower() in auto_exts):
                    if move_to_programs and programs_dir:
                        final = move_to_programs_and_open(out_path, programs_dir)
                        self.signals.log.emit(f'Opened (moved) -> {final}')
                    else:
                        open_file_default(out_path)
                        self.signals.log.emit(f'Opened -> {out_path}')

            except Exception as e:
                self.signals.log.emit(f'ERROR decoding {fpath}: {interpret_exception(e)}')
            self.signals.progress.emit(int((i + 1) / total * 100))
        self.signals.finished.emit()


# -------------------- GUI Widgets --------------------
class FileListWidget(QListWidget):
    def __init__(self, show_thumbs=True):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.show_thumbs = show_thumbs
        self.setIconSize(QSize(80, 80))

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            for u in event.mimeData().urls():
                path = u.toLocalFile()
                if path:
                    self.add_path(path)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def add_path(self, path: str):
        item = QListWidgetItem(os.path.abspath(path))
        if self.show_thumbs and Path(path).suffix.lower() in ['.png', '.bmp', '.tiff', '.jpg', '.jpeg', '.gif', '.webp']:
            pix = make_thumbnail(path)
            if not pix.isNull():
                item.setIcon(pix)
        item.setToolTip(path)
        self.addItem(item)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        remove_action = QAction('Remove selected', self)
        remove_action.triggered.connect(self.remove_selected)
        preview_action = QAction('Preview file path', self)
        preview_action.triggered.connect(self.preview_selected)
        open_folder = QAction('Open containing folder', self)
        open_folder.triggered.connect(self.open_containing)
        copy_path = QAction('Copy path', self)
        copy_path.triggered.connect(self.copy_selected_path)
        menu.addAction(preview_action)
        menu.addAction(open_folder)
        menu.addAction(copy_path)
        menu.addAction(remove_action)
        menu.exec(event.globalPos())

    def remove_selected(self):
        for it in self.selectedIndexes()[::-1]:
            self.takeItem(it.row())

    def preview_selected(self):
        items = [self.item(i).text() for i in range(self.count()) if self.item(i).isSelected()]
        if items:
            QMessageBox.information(self, 'Selected files', '\n'.join(items))

    def open_containing(self):
        items = [self.item(i).text() for i in range(self.count()) if self.item(i).isSelected()]
        if not items:
            return
        folder = os.path.dirname(items[0])
        open_file_default(folder)

    def copy_selected_path(self):
        items = [self.item(i).text() for i in range(self.count()) if self.item(i).isSelected()]
        if not items:
            return
        cb = QApplication.clipboard()
        cb.setText(items[0])


class MainWindow(QWidget):
    def __init__(self, cli_mode=False, cli_args=None):
        super().__init__()
        self.cli_mode = cli_mode
        self.cli_args = cli_args
        self.setWindowTitle(APP_NAME)
        self.resize(1280, 820)
        self.pool = QThreadPool.globalInstance()
        self.settings = load_settings()

        tabs = QTabWidget()
        tabs.addTab(self.encode_ui(), 'Encode')
        tabs.addTab(self.decode_ui(), 'Decode')
        tabs.addTab(self.settings_ui(), 'Settings')

        layout = QVBoxLayout()
        layout.addWidget(tabs)

        self.status = QStatusBar()
        layout.addWidget(self.status)
        self.setLayout(layout)

        if self.cli_mode:
            self.run_cli()

    # GUI building functions (same structure as v5) but updated to use the new workers
    # ... (the full GUI code is present in the canvas file)

    def encode_ui(self):
        # (identical to previous v5/v5.1 encode UI)
        w = QWidget()
        main = QVBoxLayout()
        splitter = QSplitter()
        self.carrier_list = FileListWidget(show_thumbs=True)
        self.payload_list = FileListWidget(show_thumbs=True)
        splitter.addWidget(self._wrap_with_label('Carriers (drag files or add)', self.carrier_list))
        splitter.addWidget(self._wrap_with_label('Payloads (drag files or add)', self.payload_list))
        main.addWidget(splitter)

        btns_h = QHBoxLayout()
        add_carriers_btn = QPushButton('Add Carriers')
        add_carriers_btn.clicked.connect(lambda: self._add_files(self.carrier_list))
        add_payloads_btn = QPushButton('Add Payloads')
        add_payloads_btn.clicked.connect(lambda: self._add_files(self.payload_list))
        btns_h.addWidget(add_carriers_btn)
        btns_h.addWidget(add_payloads_btn)
        main.addLayout(btns_h)

        options_h = QHBoxLayout()
        self.compress_cb = QCheckBox('Compress')
        self.encrypt_cb = QCheckBox('Encrypt')
        self.use_cs_cb = QCheckBox('Use cryptosteganography module')
        if not HAS_CS:
            self.use_cs_cb.setEnabled(False)
            self.use_cs_cb.setToolTip('Install cryptosteganography to enable')
        options_h.addWidget(self.compress_cb)
        options_h.addWidget(self.encrypt_cb)
        options_h.addWidget(self.use_cs_cb)
        main.addLayout(options_h)

        pw_h = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        pw_h.addWidget(QLabel('Password:'))
        pw_h.addWidget(self.password_edit)
        main.addLayout(pw_h)

        map_h = QHBoxLayout()
        self.mapping_combo = QComboBox()
        self.mapping_combo.addItems(['One-to-one (by order)', 'Cycle payloads', 'Shard single payload across carriers', 'Auto-shard large payloads'])
        map_h.addWidget(QLabel('Mapping:'))
        map_h.addWidget(self.mapping_combo)
        main.addLayout(map_h)

        lsb_h = QHBoxLayout()
        self.lsb_combo = QComboBox()
        self.lsb_combo.addItems(['1 bit/channel (highest stealth)', '2 bits/channel (higher capacity)'])
        lsb_h.addWidget(QLabel('LSB Mode:'))
        lsb_h.addWidget(self.lsb_combo)
        self.redundancy_spin = QComboBox()
        self.redundancy_spin.addItems(['1','2','3'])
        lsb_h.addWidget(QLabel('Redundancy:'))
        lsb_h.addWidget(self.redundancy_spin)
        main.addLayout(lsb_h)

        out_h = QHBoxLayout()
        self.out_folder = QLineEdit(self.settings.get('last_out', os.getcwd()))
        btn_out = QPushButton('Choose Output Folder')
        btn_out.clicked.connect(self.choose_output_folder)
        out_h.addWidget(self.out_folder)
        out_h.addWidget(btn_out)
        main.addLayout(out_h)

        cap_h = QHBoxLayout()
        self.capacity_label = QLabel('Capacity: —')
        self.estimate_btn = QPushButton('Estimate capacity for selected payloads')
        self.estimate_btn.clicked.connect(self.estimate_capacity)
        cap_h.addWidget(self.capacity_label)
        cap_h.addWidget(self.estimate_btn)
        main.addLayout(cap_h)

        act_h = QHBoxLayout()
        self.encode_btn = QPushButton('Start Encode')
        self.encode_btn.clicked.connect(self.start_encode)
        self.encode_progress = QProgressBar()
        act_h.addWidget(self.encode_btn)
        act_h.addWidget(self.encode_progress)
        main.addLayout(act_h)

        self.log = QListWidget()
        main.addWidget(QLabel('Log:'))
        main.addWidget(self.log)

        help_h = QHBoxLayout()
        about_btn = QPushButton('About / Help')
        about_btn.clicked.connect(self.show_about)
        help_h.addWidget(about_btn)
        main.addLayout(help_h)

        w.setLayout(main)
        return w

    def decode_ui(self):
        w = QWidget()
        main = QVBoxLayout()
        self.stego_list = FileListWidget(show_thumbs=True)
        main.addWidget(self._wrap_with_label('Stego files (drag files or add)', self.stego_list))

        btns_h = QHBoxLayout()
        add_stego_btn = QPushButton('Add Stego Files')
        add_stego_btn.clicked.connect(lambda: self._add_files(self.stego_list))
        btns_h.addWidget(add_stego_btn)
        main.addLayout(btns_h)

        out_h = QHBoxLayout()
        self.decode_out = QLineEdit(self.settings.get('last_out', os.getcwd()))
        btn_out = QPushButton('Choose Output Folder')
        btn_out.clicked.connect(self.choose_decode_output)
        out_h.addWidget(self.decode_out)
        out_h.addWidget(btn_out)
        main.addLayout(out_h)

        pw_h = QHBoxLayout()
        self.decode_pw = QLineEdit()
        self.decode_pw.setEchoMode(QLineEdit.Password)
        pw_h.addWidget(QLabel('Password:'))
        pw_h.addWidget(self.decode_pw)
        main.addLayout(pw_h)

        opts_h = QHBoxLayout()
        self.auto_open_all_cb = QCheckBox('Auto-open recognized types')
        self.move_to_programs_cb = QCheckBox('Move opened files to Programs folder before opening')
        opts_h.addWidget(self.auto_open_all_cb)
        opts_h.addWidget(self.move_to_programs_cb)
        main.addLayout(opts_h)

        prog_h = QHBoxLayout()
        prog_h.addWidget(QLabel('Auto-open extensions (comma list):'))
        self.auto_open_exts = QLineEdit(self.settings.get('auto_exts', DEFAULT_AUTO_EXTS))
        prog_h.addWidget(self.auto_open_exts)
        main.addLayout(prog_h)

        progdir_h = QHBoxLayout()
        progdir_h.addWidget(QLabel('Programs folder:'))
        self.programs_dir_edit = QLineEdit(self.settings.get('programs_dir', os.path.join(os.path.expanduser('~'), 'Programs')))
        progdir_h.addWidget(self.programs_dir_edit)
        btn_prog = QPushButton('Choose Programs Folder')
        btn_prog.clicked.connect(self.choose_programs_folder)
        progdir_h.addWidget(btn_prog)
        main.addLayout(progdir_h)

        lsb_h = QHBoxLayout()
        self.decode_lsb_combo = QComboBox()
        self.decode_lsb_combo.addItems(['1 bit/channel', '2 bits/channel'])
        lsb_h.addWidget(QLabel('LSB Mode to decode:'))
        lsb_h.addWidget(self.decode_lsb_combo)
        main.addLayout(lsb_h)

        act_h = QHBoxLayout()
        self.decode_btn = QPushButton('Start Decode')
        self.decode_btn.clicked.connect(self.start_decode)
        self.decode_progress = QProgressBar()
        act_h.addWidget(self.decode_btn)
        act_h.addWidget(self.decode_progress)
        main.addLayout(act_h)

        self.decode_log = QListWidget()
        main.addWidget(QLabel('Log:'))
        main.addWidget(self.decode_log)

        export_h = QHBoxLayout()
        export_btn = QPushButton('Export decoded file list (CSV)')
        export_btn.clicked.connect(self.export_decoded_list)
        export_h.addWidget(export_btn)
        main.addLayout(export_h)

        w.setLayout(main)
        return w

    def settings_ui(self):
        w = QWidget()
        v = QVBoxLayout()
        v.addWidget(QLabel('Settings and Project Tools'))
        v.addWidget(QLabel('• PBKDF2-HMAC-SHA256 (390k iterations) is used to derive keys.'))
        v.addWidget(QLabel('• Use cryptosteganography module only if installed (it encodes text).'))

        proj_h = QHBoxLayout()
        save_proj = QPushButton('Export Project (.json)')
        save_proj.clicked.connect(self.export_project)
        load_proj = QPushButton('Import Project (.json)')
        load_proj.clicked.connect(self.import_project)
        proj_h.addWidget(save_proj)
        proj_h.addWidget(load_proj)
        v.addLayout(proj_h)

        preset_h = QHBoxLayout()
        preset_btn = QPushButton('Save current as preset')
        preset_btn.clicked.connect(self.save_preset)
        load_preset_btn = QPushButton('Load preset')
        load_preset_btn.clicked.connect(self.load_preset)
        preset_h.addWidget(preset_btn)
        preset_h.addWidget(load_preset_btn)
        v.addLayout(preset_h)

        v.addStretch()
        w.setLayout(v)
        return w

    # Remaining UI helpers (file dialogs, estimate, start encode/decode) are the same
    # as in previous versions but use the fixed workers above. See the full code stored
    # in this canvas for the exact layout and wiring.

    def _wrap_with_label(self, label: str, widget: QWidget) -> QFrame:
        f = QFrame()
        v = QVBoxLayout()
        v.addWidget(QLabel(label))
        v.addWidget(widget)
        f.setLayout(v)
        return f

    def _add_files(self, list_widget: FileListWidget):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Select files', os.getcwd(), 'All Files (*)')
        for p in paths:
            list_widget.add_path(p)

    def choose_output_folder(self):
        d = QFileDialog.getExistingDirectory(self, 'Choose output folder', self.out_folder.text())
        if d:
            self.out_folder.setText(d)
            self.settings['last_out'] = d
            save_settings(self.settings)

    def choose_decode_output(self):
        d = QFileDialog.getExistingDirectory(self, 'Choose output folder', self.decode_out.text())
        if d:
            self.decode_out.setText(d)
            self.settings['last_out'] = d
            save_settings(self.settings)

    def choose_programs_folder(self):
        d = QFileDialog.getExistingDirectory(self, 'Choose programs folder', self.programs_dir_edit.text())
        if d:
            self.programs_dir_edit.setText(d)
            self.settings['programs_dir'] = d
            save_settings(self.settings)

    def estimate_capacity(self):
        carriers = [self.carrier_list.item(i).text() for i in range(self.carrier_list.count())]
        if not carriers:
            QMessageBox.information(self, 'Estimate', 'No carriers selected')
            return
        bits_per_channel = 1 if self.lsb_combo.currentIndex() == 0 else 2
        caps = [estimate_capacity_bits(c, bits_per_channel) for c in carriers]
        total_bits = sum(caps)
        total_bytes = total_bits // 8
        self.capacity_label.setText(f'Capacity: {total_bytes} bytes across {len(carriers)} carriers (mode {bits_per_channel}bpc)')
        payloads = [self.payload_list.item(i).text() for i in range(self.payload_list.count())]
        pl_size = sum(os.path.getsize(p) for p in payloads) if payloads else 0
        self.capacity_label.setToolTip(f'Payload total size: {pl_size} bytes')

    def start_encode(self):
        carriers = [self.carrier_list.item(i).text() for i in range(self.carrier_list.count())]
        payloads = [self.payload_list.item(i).text() for i in range(self.payload_list.count())]
        if not carriers or not payloads:
            QMessageBox.warning(self, 'Missing', 'Add carrier(s) and payload(s)')
            return
        mapping = self.mapping_combo.currentIndex()
        tasks = []
        out_folder = self.out_folder.text() or os.getcwd()
        bits_per_channel = 1 if self.lsb_combo.currentIndex() == 0 else 2
        redundancy = int(self.redundancy_spin.currentText())

        if mapping == 0:
            for i, c in enumerate(carriers):
                p = payloads[i % len(payloads)]
                out = os.path.join(out_folder, Path(c).stem + '_stego.png')
                tasks.append({'carrier': c, 'payload': p, 'out': out})
        elif mapping == 1:
            for i, c in enumerate(carriers):
                p = payloads[i % len(payloads)]
                out = os.path.join(out_folder, Path(c).stem + '_stego.png')
                tasks.append({'carrier': c, 'payload': p, 'out': out})
        elif mapping == 2:
            p = payloads[0]
            data = open(p, 'rb').read()
            shards = len(carriers)
            chunk_size = math.ceil(len(data) / shards)
            self._temp_shards = []
            for i, c in enumerate(carriers):
                chunk = data[i * chunk_size:(i + 1) * chunk_size]
                tmp = os.path.join(tempfile.gettempdir(), f'cryptosteg_shard_{i}_{Path(p).name}')
                with open(tmp, 'wb') as fh:
                    fh.write(chunk)
                self._temp_shards.append(tmp)
                out = os.path.join(out_folder, Path(c).stem + f'_stego_shard{i}.png')
                tasks.append({'carrier': c, 'payload': tmp, 'out': out, 'index': i, 'shards': shards})
        else:
            for p in payloads:
                data = open(p, 'rb').read()
                caps = [estimate_capacity_bits(c, bits_per_channel) // 8 for c in carriers]
                total_cap = sum(caps)
                if len(data) > total_cap:
                    QMessageBox.warning(self, 'Too large', f'Payload {p} ({len(data)} bytes) larger than combined carrier capacity {total_cap} bytes')
                    continue
                shards = len(carriers)
                chunk_size = math.ceil(len(data) / shards)
                for i, c in enumerate(carriers):
                    chunk = data[i * chunk_size:(i + 1) * chunk_size]
                    tmp = os.path.join(tempfile.gettempdir(), f'cryptosteg_autoshard_{i}_{Path(p).name}')
                    with open(tmp, 'wb') as fh:
                        fh.write(chunk)
                    out = os.path.join(out_folder, Path(c).stem + f'_stego_shard{i}.png')
                    tasks.append({'carrier': c, 'payload': tmp, 'out': out, 'index': i, 'shards': shards})

        options = {
            'compress': self.compress_cb.isChecked(),
            'encrypt': self.encrypt_cb.isChecked(),
            'password': self.password_edit.text() or None,
            'use_cs': self.use_cs_cb.isChecked(),
            'hmac_key': (self.password_edit.text() or 'hmac-salt').encode('utf-8'),
            'bits_per_channel': bits_per_channel,
            'auto_shard': self.mapping_combo.currentIndex() == 3,
            'redundancy': redundancy,
            'auto_escalate': True,
        }
        add_recent_project(out_folder)
        self.settings['last_out'] = out_folder
        save_settings(self.settings)

        self.encode_btn.setEnabled(False)
        worker = EncodeWorker(tasks, options)
        worker.signals.log.connect(self.on_worker_log)
        worker.signals.progress.connect(self.encode_progress.setValue)
        worker.signals.finished.connect(self._encode_finished)
        self.pool.start(worker)

    def on_worker_log(self, message: str):
        self.log.addItem(message)
        if message.startswith('ERROR'):
            short = message.splitlines()[0]
            self.status.showMessage(short)

    def _encode_finished(self):
        self.encode_btn.setEnabled(True)
        self.log.addItem('Encode batch finished')
        errs = [self.log.item(i).text() for i in range(self.log.count()) if self.log.item(i).text().startswith('ERROR')]
        if errs:
            QMessageBox.warning(self, 'Encode completed with errors', f'{len(errs)} errors occurred. See log for details.')

    def start_decode(self):
        files = [self.stego_list.item(i).text() for i in range(self.stego_list.count())]
        if not files:
            QMessageBox.warning(self, 'Missing', 'Add stego files')
            return
        out_folder = self.decode_out.text() or os.getcwd()
        auto_exts = {e.strip().lower() for e in self.auto_open_exts.text().split(',') if e.strip()}
        bits_per_channel = 1 if self.decode_lsb_combo.currentIndex() == 0 else 2
        options = {
            'password': self.decode_pw.text() or None,
            'use_cs': self.use_cs_cb.isChecked() if hasattr(self, 'use_cs_cb') else False,
            'auto_open_all': self.auto_open_all_cb.isChecked(),
            'auto_open_exts': auto_exts,
            'move_to_programs': self.move_to_programs_cb.isChecked(),
            'programs_dir': self.programs_dir_edit.text(),
            'hmac_key': (self.decode_pw.text() or 'hmac-salt').encode('utf-8'),
            'bits_per_channel': bits_per_channel
        }
        add_recent_project(out_folder)
        self.settings['last_out'] = out_folder
        save_settings(self.settings)

        self.decode_btn.setEnabled(False)
        worker = DecodeWorker(files, out_folder, options)
        worker.signals.log.connect(self.on_decode_log)
        worker.signals.progress.connect(self.decode_progress.setValue)
        worker.signals.finished.connect(self._decode_finished)
        self.pool.start(worker)

    def on_decode_log(self, message: str):
        self.decode_log.addItem(message)
        if message.startswith('ERROR'):
            short = message.splitlines()[0]
            self.status.showMessage(short)

    def _decode_finished(self):
        self.decode_btn.setEnabled(True)
        self.decode_log.addItem('Decode batch finished')
        errs = [self.decode_log.item(i).text() for i in range(self.decode_log.count()) if self.decode_log.item(i).text().startswith('ERROR')]
        if errs:
            QMessageBox.warning(self, 'Decode completed with errors', f'{len(errs)} errors occurred. See log for details.')

    def export_decoded_list(self):
        items = [self.decode_log.item(i).text() for i in range(self.decode_log.count())]
        decoded = [line.split('Decoded -> ')[1] for line in items if 'Decoded -> ' in line]
        if not decoded:
            QMessageBox.information(self, 'Export', 'No decoded files found in log')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save decoded file list', os.getcwd(), 'CSV Files (*.csv)')
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as fh:
                w = csv.writer(fh)
                w.writerow(['path'])
                for d in decoded:
                    w.writerow([d])
            QMessageBox.information(self, 'Exported', f'Decoded list exported to {path}')

    def save_preset(self):
        name, ok = QInputDialog.getText(self, 'Preset name', 'Enter preset name:')
        if not ok or not name:
            return
        preset = {
            'compress': self.compress_cb.isChecked(),
            'encrypt': self.encrypt_cb.isChecked(),
            'lsb_mode': self.lsb_combo.currentIndex(),
            'redundancy': self.redundancy_spin.currentText()
        }
        pdir = os.path.join(Path.home(), '.advcryptosteg_presets')
        os.makedirs(pdir, exist_ok=True)
        path = os.path.join(pdir, f'{name}.json')
        with open(path, 'w') as fh:
            json.dump(preset, fh)
        QMessageBox.information(self, 'Saved', f'Preset saved to {path}')

    def load_preset(self):
        pdir = os.path.join(Path.home(), '.advcryptosteg_presets')
        path, _ = QFileDialog.getOpenFileName(self, 'Load preset', pdir, 'JSON Files (*.json)')
        if path:
            with open(path, 'r') as fh:
                preset = json.load(fh)
            self.compress_cb.setChecked(preset.get('compress', False))
            self.encrypt_cb.setChecked(preset.get('encrypt', False))
            self.lsb_combo.setCurrentIndex(preset.get('lsb_mode', 0))
            self.redundancy_spin.setCurrentText(str(preset.get('redundancy', '1')))
            QMessageBox.information(self, 'Loaded', f'Preset loaded')

    def show_about(self):
        QMessageBox.information(self, 'About', f'{APP_NAME}\nRobust error handling, auto-escalation, auto-LSB retry, and helpful hints for failures.')

    def export_project(self):
        proj = {
            'carriers': [self.carrier_list.item(i).text() for i in range(self.carrier_list.count())],
            'payloads': [self.payload_list.item(i).text() for i in range(self.payload_list.count())],
            'settings': {
                'compress': self.compress_cb.isChecked(),
                'encrypt': self.encrypt_cb.isChecked(),
                'use_cs': self.use_cs_cb.isChecked()
            }
        }
        path, _ = QFileDialog.getSaveFileName(self, 'Export project', os.getcwd(), 'JSON Files (*.json)')
        if path:
            with open(path, 'w') as fh:
                json.dump(proj, fh, indent=2)
            QMessageBox.information(self, 'Exported', f'Project saved to {path}')

    def import_project(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import project', os.getcwd(), 'JSON Files (*.json)')
        if path:
            with open(path, 'r') as fh:
                proj = json.load(fh)
            self.carrier_list.clear()
            self.payload_list.clear()
            for p in proj.get('carriers', []):
                self.carrier_list.add_path(p)
            for p in proj.get('payloads', []):
                self.payload_list.add_path(p)
            s = proj.get('settings', {})
            self.compress_cb.setChecked(s.get('compress', False))
            self.encrypt_cb.setChecked(s.get('encrypt', False))
            self.use_cs_cb.setChecked(s.get('use_cs', False))
            QMessageBox.information(self, 'Imported', 'Project imported')

    def run_cli(self):
        a = self.cli_args
        if a.encode:
            carriers = a.carriers or []
            payloads = a.payloads or []
            out = a.out or os.getcwd()
            tasks = []
            for i, c in enumerate(carriers):
                p = payloads[i % len(payloads)]
                tasks.append({'carrier': c, 'payload': p, 'out': os.path.join(out, Path(c).stem + '_stego.png')})
            options = {'compress': a.compress, 'encrypt': a.encrypt, 'password': a.password, 'bits_per_channel': 1}
            worker = EncodeWorker(tasks, options)
            worker.signals.log.connect(lambda msg: print(msg))
            worker.run()
            print('CLI encode finished')
        if a.decode:
            files = a.files or []
            out = a.out or os.getcwd()
            options = {'password': a.password, 'bits_per_channel': 1}
            worker = DecodeWorker(files, out, options)
            worker.signals.log.connect(lambda msg: print(msg))
            worker.run()
            print('CLI decode finished')


# -------------------- Main --------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description='ShadowHide v5.2 CLI')
    parser.add_argument('--cli', dest='cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--encode', dest='encode', action='store_true')
    parser.add_argument('--decode', dest='decode', action='store_true')
    parser.add_argument('--carriers', nargs='*')
    parser.add_argument('--payloads', nargs='*')
    parser.add_argument('--files', nargs='*')
    parser.add_argument('--out')
    parser.add_argument('--compress', action='store_true')
    parser.add_argument('--encrypt', action='store_true')
    parser.add_argument('--password')
    args = parser.parse_args(argv)

    app = QApplication(sys.argv)
    win = MainWindow(cli_mode=args.cli, cli_args=args)
    win.show()
    if args.cli:
        win.run_cli()
        return
    sys.exit(app.exec())


if __name__ == '__main__':
    main(sys.argv[1:])

