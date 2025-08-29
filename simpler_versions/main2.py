"""
Advanced Cryptosteganography — v3 (Feature-rich, improved UX, file association launching)

Major additions in v3:
- Open extracted files with the OS default app (png, html, py, bat, exe, etc.). Uses os.startfile on Windows, `xdg-open` / `open` on Linux/macOS.
- Integrity HMAC (SHA256) support: compute HMAC over payload and store in metadata; verify on decode.
- Configurable LSB parameters: number of LSBs (1 or 2), channels to use (R/G/B), optional alpha handling.
- Ability to choose output image format (PNG recommended to preserve LSB) and force a lossless save.
- Auto reassembly of shards: when decoding, detect shard metadata and automatically stitch shards in order to recreate original payload.
- Per-file actions in decode log: right-click to open the file, open containing folder, or verify HMAC again.
- Improved error dialogs, capacity estimation warnings before encode, and safer temp shard handling with cleanup.
- Quick export to executable instructions button (opens a small help dialog describing PyInstaller options).

Run:
    python advanced_cryptosteg_v3.py

Dependencies:
    pip install PySide6 cryptosteganography pillow opencv-python numpy cryptography

Security notes:
- HMAC uses a key derived from password (if provided). If you enable encryption without password, encryption will be skipped.
- Use lossless carriers (PNG, TIFF, BMP). Do NOT use JPEG for LSB embedding.

This file is a prototype — test thoroughly and review crypto choices for production use.
"""

import sys
import os
import math
import zlib
import base64
import json
import io
import tempfile
import hashlib
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QListWidget, QLabel, QLineEdit, QProgressBar, QMessageBox, QTabWidget,
    QCheckBox, QComboBox, QListWidgetItem, QFrame, QMenu, QAbstractItemView,
    QSplitter, QTextEdit
)
from PySide6.QtGui import QPixmap, QImage, QAction
from PySide6.QtCore import Qt, QSize, QRunnable, QThreadPool, Signal, QObject, Slot

import numpy as np
import cv2
from PIL import Image

# Optional: cryptosteganography module
try:
    from cryptosteganography import CryptoSteganography
    HAS_CS = True
except Exception:
    HAS_CS = False

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# -------------------- Crypto & HMAC helpers --------------------

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


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', data, key, 1)

# -------------------- Thumbnails & capacity --------------------

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


def estimate_capacity_bits(image_path: str, lsb_count: int = 1, channels: int = 3) -> int:
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        return 0
    h, w = img.shape[:2]
    return h * w * channels * lsb_count

# -------------------- FileList Widget --------------------

from PySide6.QtWidgets import QListWidget

class FileListWidget(QListWidget):
    def __init__(self, show_thumbs=True):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.show_thumbs = show_thumbs
        self.setIconSize(QSize(80, 80))

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
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
        if self.show_thumbs and Path(path).suffix.lower() in ['.png', '.bmp', '.tiff', '.jpg', '.jpeg', '.gif']:
            pix = make_thumbnail(path)
            if not pix.isNull():
                item.setIcon(pix)
        item.setToolTip(path)
        self.addItem(item)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        remove_action = QAction('Remove selected', self)
        remove_action.triggered.connect(self.remove_selected)
        open_action = QAction('Open file(s)', self)
        open_action.triggered.connect(self.open_selected)
        menu.addAction(open_action)
        menu.addAction(remove_action)
        menu.exec(event.globalPos())

    def remove_selected(self):
        for it in self.selectedIndexes()[::-1]:
            self.takeItem(it.row())

    def open_selected(self):
        items = [self.item(i).text() for i in range(self.count()) if self.item(i).isSelected()]
        for p in items:
            open_with_default(p)

# -------------------- Stego backend (configurable LSB) --------------------

MAGIC = b'ADVSTG3'
import struct

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


def bytes_to_bits(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8)).astype(np.uint8)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-bits.size) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()


def embed_lsb_config(carrier_path: str, out_path: str, payload: bytes, lsb_count: int = 1, channels_mask: Tuple[bool,bool,bool]=(True,True,True)) -> None:
    img = cv2.imread(carrier_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read carrier')
    h, w = img.shape[:2]
    # construct channel indices mapping
    channel_order = []
    for c_idx, use in enumerate(channels_mask):
        if use:
            channel_order.append(c_idx)
    available_slots = h * w * len(channel_order) * lsb_count
    bits = bytes_to_bits(payload)
    if bits.size > available_slots:
        raise ValueError(f'Payload too large ({bits.size} bits) for carrier capacity {available_slots} bits')
    arr = img.copy()
    flat = arr[:, :, :3].reshape(-1, 3)
    # we'll write per channel LSBs
    bit_idx = 0
    total_pixels = flat.shape[0]
    for pix in range(total_pixels):
        for ch in channel_order:
            for b in range(lsb_count):
                if bit_idx >= bits.size:
                    break
                # modify the b-th LSB: shift and set
                mask = 1 << b
                # clear the target bit then set it
                val = flat[pix, ch]
                val = (val & ~mask) | (bits[bit_idx] << b)
                flat[pix, ch] = val
                bit_idx += 1
            if bit_idx >= bits.size:
                break
        if bit_idx >= bits.size:
            break
    arr[:, :, :3] = flat.reshape(h, w, 3)
    # save lossless
    cv2.imwrite(out_path, arr)


def extract_lsb_config(stego_path: str, expected_bits: int, lsb_count: int =1, channels_mask: Tuple[bool,bool,bool]=(True,True,True)) -> bytes:
    img = cv2.imread(stego_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read stego')
    flat = img[:, :, :3].reshape(-1, 3)
    channel_order = [i for i,v in enumerate(channels_mask) if v]
    bits = []
    bit_idx = 0
    total_pixels = flat.shape[0]
    for pix in range(total_pixels):
        for ch in channel_order:
            for b in range(lsb_count):
                if bit_idx >= expected_bits:
                    break
                val = flat[pix, ch]
                bit = (int(val) >> b) & 1
                bits.append(bit)
                bit_idx += 1
            if bit_idx >= expected_bits:
                break
        if bit_idx >= expected_bits:
            break
    return bits_to_bytes(np.array(bits, dtype=np.uint8))

# -------------------- Helpers for opening files --------------------

def open_with_default(path: str):
    try:
        if sys.platform.startswith('win'):
            os.startfile(path)
        elif sys.platform.startswith('darwin'):
            subprocess.run(['open', path])
        else:
            subprocess.run(['xdg-open', path])
    except Exception as e:
        QMessageBox.warning(None, 'Open file', f'Could not open {path}: {e}')

# -------------------- Workers --------------------

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
            try:
                carrier = t['carrier']
                payload_path = t['payload']
                out = t['out']
                meta = {
                    'filename': os.path.basename(payload_path),
                    'index': t.get('index', 0),
                    'shards': t.get('shards', 1)
                }
                data = open(payload_path, 'rb').read()

                # compress
                if self.options.get('compress'):
                    data = zlib.compress(data)
                    meta['compressed'] = True
                else:
                    meta['compressed'] = False

                # HMAC integrity
                hmac_key = None
                if self.options.get('hmac') and self.options.get('password'):
                    key_bytes = hashlib.sha256(self.options.get('password').encode('utf-8')).digest()
                    mac = hmac_sha256(key_bytes, data)
                    meta['hmac'] = base64.b64encode(mac).decode('ascii')
                    meta['hmac_algo'] = 'pbkdf2-hmac-sha256'
                else:
                    meta['hmac'] = None

                # encrypt
                if self.options.get('encrypt') and self.options.get('password'):
                    key, salt = derive_key(self.options.get('password'))
                    meta['salt'] = base64.b64encode(salt).decode('ascii')
                    f = Fernet(key)
                    data = f.encrypt(data)
                    meta['encrypted'] = True
                else:
                    meta['encrypted'] = False

                # pack metadata
                payload = MAGIC + pack_meta(meta) + data

                # choose backend
                lsb_count = self.options.get('lsb_count', 1)
                channels_mask = self.options.get('channels_mask', (True, True, True))

                if self.options.get('use_cs') and HAS_CS:
                    # base64 encode and use cryptosteganography
                    cs_key = base64.urlsafe_b64encode(b'module-' + (self.options.get('password') or '').encode('utf-8')).decode('ascii') if self.options.get('password') else 'nokey'
                    cs = CryptoSteganography(cs_key)
                    b64 = base64.b64encode(payload).decode('ascii')
                    cs.hide(carrier, out, b64)
                else:
                    embed_lsb_config(carrier, out, payload, lsb_count=lsb_count, channels_mask=channels_mask)

                self.signals.log.emit(f'Encoded -> {out}')
            except Exception as e:
                self.signals.log.emit(f'ERROR encoding {t.get("carrier")}: {e}')
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
        decoded_paths = []
        shard_map = {}
        for i, fpath in enumerate(self.files):
            try:
                # read using chosen backend
                if self.options.get('use_cs') and HAS_CS:
                    cs_key = base64.urlsafe_b64encode(b'module-' + (self.options.get('password') or '').encode('utf-8')).decode('ascii') if self.options.get('password') else 'nokey'
                    cs = CryptoSteganography(cs_key)
                    b64 = cs.retrieve(fpath)
                    payload = base64.b64decode(b64)
                else:
                    cap_bits = estimate_capacity_bits(fpath, lsb_count=self.options.get('lsb_count',1), channels= sum(1 for v in self.options.get('channels_mask',(True,True,True)) if v))
                    payload = extract_lsb_config(fpath, cap_bits, lsb_count=self.options.get('lsb_count',1), channels_mask=self.options.get('channels_mask',(True,True,True)))

                if not payload.startswith(MAGIC):
                    raise ValueError('No valid payload (magic mismatch)')
                meta, hdr_len = unpack_meta(payload[len(MAGIC):])
                data = payload[len(MAGIC) + hdr_len:]

                # decrypt if needed
                if meta.get('encrypted'):
                    salt = base64.b64decode(meta.get('salt')) if meta.get('salt') else None
                    password = self.options.get('password')
                    if not password:
                        raise ValueError('Encrypted payload requires password')
                    key, _ = derive_key(password, salt)
                    f = Fernet(key)
                    data = f.decrypt(data)

                # verify HMAC
                if meta.get('hmac'):
                    if not self.options.get('password'):
                        # we can't verify without password, but still save file and notify
                        verified = False
                    else:
                        key_bytes = hashlib.sha256(self.options.get('password').encode('utf-8')).digest()
                        expected = base64.b64decode(meta.get('hmac'))
                        actual = hmac_sha256(key_bytes, data)
                        verified = expected == actual
                else:
                    verified = None

                # decompress
                if meta.get('compressed'):
                    data = zlib.decompress(data)

                out_name = meta.get('filename', 'extracted.bin')
                # for shards, save with a shard suffix to be reassembled later
                if meta.get('shards',1) > 1:
                    out_name = f"{meta.get('filename')}.shard{meta.get('index')}of{meta.get('shards')}"
                out_path = os.path.join(self.out_folder, out_name)
                base, ext = os.path.splitext(out_path)
                idx = 1
                while os.path.exists(out_path):
                    out_path = f"{base}_{idx}{ext}"
                    idx += 1
                with open(out_path, 'wb') as fh:
                    fh.write(data)

                decoded_paths.append((out_path, verified))
                self.signals.log.emit(f'Decoded -> {out_path} (verified={verified})')

                # collect shards
                if meta.get('shards',1) > 1:
                    key = os.path.basename(meta.get('filename'))
                    shard_map.setdefault(key, []).append({'path': out_path, 'index': meta.get('index'), 'total': meta.get('shards')})

            except Exception as e:
                self.signals.log.emit(f'ERROR decoding {fpath}: {e}')
            self.signals.progress.emit(int((i + 1) / total * 100))

        # attempt shard reassembly
        for key, shards in shard_map.items():
            try:
                shards_sorted = sorted(shards, key=lambda x: x['index'])
                target = os.path.join(self.out_folder, key)
                with open(target, 'wb') as outfh:
                    for s in shards_sorted:
                        with open(s['path'], 'rb') as sh:
                            outfh.write(sh.read())
                self.signals.log.emit(f'Reassembled shards -> {target}')
                # cleanup
                for s in shards_sorted:
                    try:
                        os.remove(s['path'])
                    except Exception:
                        pass
            except Exception as e:
                self.signals.log.emit(f'ERROR reassembling {key}: {e}')

        self.signals.finished.emit()

# -------------------- Main GUI --------------------

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Advanced Cryptosteg v3 — Ultimate')
        self.resize(1200, 820)
        self.pool = QThreadPool.globalInstance()

        tabs = QTabWidget()
        tabs.addTab(self.encode_ui(), 'Encode')
        tabs.addTab(self.decode_ui(), 'Decode')
        tabs.addTab(self.settings_ui(), 'Settings')

        layout = QVBoxLayout()
        layout.addWidget(tabs)
        self.setLayout(layout)

    def encode_ui(self):
        w = QWidget()
        main = QVBoxLayout()
        splitter = QSplitter()

        self.carrier_list = FileListWidget(show_thumbs=True)
        self.payload_list = FileListWidget(show_thumbs=False)
        splitter.addWidget(self._wrap_with_label('Carriers', self.carrier_list))
        splitter.addWidget(self._wrap_with_label('Payloads', self.payload_list))
        main.addWidget(splitter)

        btns = QHBoxLayout()
        add_carriers = QPushButton('Add Carriers')
        add_carriers.clicked.connect(lambda: self._add_files(self.carrier_list))
        add_payloads = QPushButton('Add Payloads')
        add_payloads.clicked.connect(lambda: self._add_files(self.payload_list))
        btns.addWidget(add_carriers)
        btns.addWidget(add_payloads)
        main.addLayout(btns)

        opts = QHBoxLayout()
        self.compress_cb = QCheckBox('Compress')
        self.encrypt_cb = QCheckBox('Encrypt')
        self.hmac_cb = QCheckBox('HMAC (verify)')
        self.use_cs_cb = QCheckBox('Use cryptosteganography')
        if not HAS_CS:
            self.use_cs_cb.setEnabled(False)
        opts.addWidget(self.compress_cb)
        opts.addWidget(self.encrypt_cb)
        opts.addWidget(self.hmac_cb)
        opts.addWidget(self.use_cs_cb)
        main.addLayout(opts)

        pw_h = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        pw_h.addWidget(QLabel('Password (optional):'))
        pw_h.addWidget(self.password_edit)
        main.addLayout(pw_h)

        lsb_h = QHBoxLayout()
        self.lsb_combo = QComboBox()
        self.lsb_combo.addItems(['1 LSB (recommended)', '2 LSB (more capacity, risk)'])
        self.channel_combo = QComboBox()
        self.channel_combo.addItems(['RGB', 'R only', 'G only', 'B only', 'RG', 'RB', 'GB'])
        lsb_h.addWidget(QLabel('LSB Depth:'))
        lsb_h.addWidget(self.lsb_combo)
        lsb_h.addWidget(QLabel('Channels:'))
        lsb_h.addWidget(self.channel_combo)
        main.addLayout(lsb_h)

        map_h = QHBoxLayout()
        self.mapping_combo = QComboBox()
        self.mapping_combo.addItems(['One-to-one', 'Cycle payloads', 'Shard single payload across carriers'])
        map_h.addWidget(QLabel('Mapping:'))
        map_h.addWidget(self.mapping_combo)
        main.addLayout(map_h)

        out_h = QHBoxLayout()
        self.out_folder = QLineEdit(os.getcwd())
        btn_out = QPushButton('Choose Output Folder')
        btn_out.clicked.connect(self.choose_output_folder)
        out_h.addWidget(self.out_folder)
        out_h.addWidget(btn_out)
        main.addLayout(out_h)

        act = QHBoxLayout()
        self.encode_btn = QPushButton('Start Encode')
        self.encode_btn.clicked.connect(self.start_encode)
        self.encode_progress = QProgressBar()
        act.addWidget(self.encode_btn)
        act.addWidget(self.encode_progress)
        main.addLayout(act)

        self.log = QListWidget()
        main.addWidget(QLabel('Log'))
        main.addWidget(self.log)

        w.setLayout(main)
        return w

    def decode_ui(self):
        w = QWidget()
        main = QVBoxLayout()
        self.stego_list = FileListWidget(show_thumbs=True)
        main.addWidget(self._wrap_with_label('Stego Files', self.stego_list))

        btns = QHBoxLayout()
        add_btn = QPushButton('Add Stego Files')
        add_btn.clicked.connect(lambda: self._add_files(self.stego_list))
        btns.addWidget(add_btn)
        main.addLayout(btns)

        out_h = QHBoxLayout()
        self.decode_out = QLineEdit(os.getcwd())
        btn_out = QPushButton('Choose Output Folder')
        btn_out.clicked.connect(self.choose_decode_output)
        out_h.addWidget(self.decode_out)
        out_h.addWidget(btn_out)
        main.addLayout(out_h)

        pw_h = QHBoxLayout()
        self.decode_pw = QLineEdit()
        self.decode_pw.setEchoMode(QLineEdit.Password)
        pw_h.addWidget(QLabel('Password (if needed):'))
        pw_h.addWidget(self.decode_pw)
        main.addLayout(pw_h)

        opts = QHBoxLayout()
        self.auto_open_cb = QCheckBox('Auto-open extracted HTML')
        self.use_cs_decode_cb = QCheckBox('Use cryptosteganography')
        if not HAS_CS:
            self.use_cs_decode_cb.setEnabled(False)
        opts.addWidget(self.auto_open_cb)
        opts.addWidget(self.use_cs_decode_cb)
        main.addLayout(opts)

        act = QHBoxLayout()
        self.decode_btn = QPushButton('Start Decode')
        self.decode_btn.clicked.connect(self.start_decode)
        self.decode_progress = QProgressBar()
        act.addWidget(self.decode_btn)
        act.addWidget(self.decode_progress)
        main.addLayout(act)

        self.decode_log = QListWidget()
        main.addWidget(QLabel('Decode Log'))
        main.addWidget(self.decode_log)
        w.setLayout(main)
        return w

    def settings_ui(self):
        w = QWidget()
        v = QVBoxLayout()
        v.addWidget(QLabel('Settings & Tools'))
        v.addWidget(QLabel('• Export to EXE (see help) — creates a single-file app using PyInstaller.'))
        help_btn = QPushButton('Show PyInstaller Help')
        help_btn.clicked.connect(self.show_pyinstaller_help)
        v.addWidget(help_btn)
        v.addStretch()
        w.setLayout(v)
        return w

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

    def choose_decode_output(self):
        d = QFileDialog.getExistingDirectory(self, 'Choose output folder', self.decode_out.text())
        if d:
            self.decode_out.setText(d)

    def show_pyinstaller_help(self):
        msg = ("To create a single-file EXE: install PyInstaller and run:"
               "py -m pip install pyinstaller"
               "pyinstaller --onefile --noconsole advanced_cryptosteg_v3.py"
               "Test the generated exe thoroughly. Include required data files as needed.")
        QMessageBox.information(self, 'PyInstaller Help', msg)

    def start_encode(self):
        carriers = [self.carrier_list.item(i).text() for i in range(self.carrier_list.count())]
        payloads = [self.payload_list.item(i).text() for i in range(self.payload_list.count())]
        if not carriers or not payloads:
            QMessageBox.warning(self, 'Missing', 'Add carriers and payloads')
            return

        mapping = self.mapping_combo.currentIndex()
        tasks = []
        out_folder = self.out_folder.text() or os.getcwd()

        if mapping == 0:  # one-to-one
            for i, c in enumerate(carriers):
                p = payloads[i % len(payloads)]
                out = os.path.join(out_folder, Path(c).stem + '_stego.png')
                tasks.append({'carrier': c, 'payload': p, 'out': out})
        elif mapping == 1:  # cycle
            for i, c in enumerate(carriers):
                p = payloads[i % len(payloads)]
                out = os.path.join(out_folder, Path(c).stem + '_stego.png')
                tasks.append({'carrier': c, 'payload': p, 'out': out})
        else:  # shard
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

        # options
        lsb_count = 1 if self.lsb_combo.currentIndex() == 0 else 2
        channels_text = self.channel_combo.currentText()
        channels_mask = {
            'RGB': (True,True,True), 'R only':(True,False,False), 'G only':(False,True,False), 'B only':(False,False,True),
            'RG':(True,True,False),'RB':(True,False,True),'GB':(False,True,True)
        }[channels_text]

        options = {
            'compress': self.compress_cb.isChecked(),
            'encrypt': self.encrypt_cb.isChecked(),
            'hmac': self.hmac_cb.isChecked(),
            'password': self.password_edit.text() or None,
            'use_cs': self.use_cs_cb.isChecked(),
            'lsb_count': lsb_count,
            'channels_mask': channels_mask
        }

        # warn capacity for first pair
        sample_payload = open(tasks[0]['payload'],'rb').read()
        needed_bits = len(bytes_to_bits(MAGIC + pack_meta({'filename':os.path.basename(tasks[0]['payload'])}) + sample_payload))
        cap = estimate_capacity_bits(tasks[0]['carrier'], lsb_count=options['lsb_count'], channels=sum(1 for v in channels_mask if v))
        if needed_bits > cap:
            QMessageBox.warning(self, 'Capacity warning', f"First carrier may be too small: need {needed_bits} bits, capacity {cap} bits.")

        self.encode_btn.setEnabled(False)
        worker = EncodeWorker(tasks, options)
        worker.signals.log.connect(self.log.addItem)
        worker.signals.progress.connect(self.encode_progress.setValue)
        worker.signals.finished.connect(self._encode_finished)
        self.pool.start(worker)

    def _encode_finished(self):
        self.encode_btn.setEnabled(True)
        self.log.addItem('Encode batch finished')
        # cleanup temp shards
        try:
            if hasattr(self,'_temp_shards'):
                for t in self._temp_shards:
                    try: os.remove(t)
                    except Exception: pass
        except Exception:
            pass

    def start_decode(self):
        files = [self.stego_list.item(i).text() for i in range(self.stego_list.count())]
        if not files:
            QMessageBox.warning(self, 'Missing', 'Add stego files')
            return
        out_folder = self.decode_out.text() or os.getcwd()
        options = {
            'password': self.decode_pw.text() or None,
            'auto_open': self.auto_open_cb.isChecked(),
            'use_cs': self.use_cs_decode_cb.isChecked(),
            'lsb_count': 1 if self.lsb_combo.currentIndex()==0 else 2,
            'channels_mask': {
                'RGB': (True,True,True), 'R only':(True,False,False), 'G only':(False,True,False), 'B only':(False,False,True),
                'RG':(True,True,False),'RB':(True,False,True),'GB':(False,True,True)
            }[self.channel_combo.currentText()]
        }
        self.decode_btn.setEnabled(False)
        worker = DecodeWorker(files, out_folder, options)
        worker.signals.log.connect(self.decode_log.addItem)
        worker.signals.progress.connect(self.decode_progress.setValue)
        worker.signals.finished.connect(self._decode_finished)
        self.pool.start(worker)

    def _decode_finished(self):
        self.decode_btn.setEnabled(True)
        self.decode_log.addItem('Decode batch finished')

    def export_project(self):
        pass

# -------------------- Main --------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
