# Advanced Cryptosteganography — v4
# Full program source: GUI + robust LSB encode/decode that can hide ANY file (images, mp3, exe, etc.)
# Features:
# - Accepts arbitrary payloads and carriers
# - Converts carriers to lossless single-frame PNG for safe embedding
# - Embedding format: MAGIC || 4-byte meta-length || meta-json || payload-bytes
#   meta includes filename, mimetype, payload_len, compressed/encrypted flags, salt, hmac
# - Decode reads only the required bits (first header then payload) so extraction works reliably
# - Optional compression and encryption (Fernet with PBKDF2-derived key)
# - Optional cryptosteganography module fallback
# - Auto-open extracted files and move-to-programs option
# - UI for selecting carriers/payloads, mapping strategies (one-to-one, cycle, shard)

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
from pathlib import Path
from typing import List, Optional, Tuple

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QListWidget, QListWidgetItem, QLabel, QLineEdit, QProgressBar, QMessageBox, QTabWidget,
    QCheckBox, QComboBox, QFrame, QMenu, QAbstractItemView, QSplitter
)
from PySide6.QtGui import QPixmap, QImage, QDragEnterEvent, QDropEvent, QAction
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
MAGIC = b'ADVSTG4'  # magic signature

LOSSLESS_EXTS = {'.png', '.bmp', '.tiff', '.tif'}


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
    If already a acceptable lossless PNG/BMP/TIFF, return original.
    Otherwise convert to a temp PNG and return path.
    """
    ext = Path(path).suffix.lower()
    if ext in LOSSLESS_EXTS and ext != '.webp':
        return path
    try:
        img = Image.open(path)
        # take first frame if animated
        img = img.convert('RGBA')
        tmp = os.path.join(tempfile.gettempdir(), f'cryptosteg_carrier_{Path(path).stem}_{os.getpid()}.png')
        img.save(tmp, format='PNG')
        return tmp
    except Exception:
        return path


def estimate_capacity_bits(image_path: str) -> int:
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        return 0
    h, w = img.shape[:2]
    channels = 3  # use RGB channels only
    return h * w * channels


# -------------------- Bit helpers --------------------

def bytes_to_bits(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8)).astype(np.uint8)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-bits.size) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()


def read_lsb_bits_array(image_path: str) -> np.ndarray:
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read image for LSB extraction')
    flat = img[:, :, :3].reshape(-1)
    return flat & 1


def read_bits_range(image_path: str, start_bit: int, num_bits: int) -> np.ndarray:
    """Read num_bits starting at start_bit (0-indexed) from the image LSB stream."""
    bits = read_lsb_bits_array(image_path)
    end = start_bit + num_bits
    if end > bits.size:
        # pad with zeros if asking beyond image capacity
        padded = np.zeros(end, dtype=np.uint8)
        padded[:bits.size] = bits
        return padded[start_bit:end]
    return bits[start_bit:end]


# -------------------- Embedding / Extraction --------------------

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


def embed_lsb(carrier_path: str, out_path: str, payload: bytes) -> None:
    carrier_for_use = ensure_single_frame_image(carrier_path)
    img = cv2.imread(carrier_for_use, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError('Could not read carrier')
    h, w = img.shape[:2]
    channels = 3
    cap = h * w * channels
    bits = bytes_to_bits(payload)
    if bits.size > cap:
        raise ValueError(f'Payload too large ({bits.size} bits) for carrier capacity {cap} bits')
    arr = img.copy()
    flat = arr[:, :, :3].reshape(-1)
    flat[:bits.size] = (flat[:bits.size] & ~1) | bits
    arr[:, :, :3] = flat.reshape(h, w, 3)
    out_path2 = os.path.splitext(out_path)[0] + '.png'
    success = cv2.imwrite(out_path2, arr)
    if not success:
        raise IOError('Failed to write stego image')


def extract_payload_from_image(stego_path: str) -> bytes:
    # Step 1: read first (MAGIC + 4 bytes) to get meta len
    header_len_bytes = len(MAGIC) + 4
    header_len_bits = header_len_bytes * 8
    first_bits = read_bits_range(stego_path, 0, header_len_bits)
    first_bytes = bits_to_bytes(first_bits)
    if not first_bytes.startswith(MAGIC):
        raise ValueError('No valid payload (magic mismatch)')
    # read meta length (4-byte big-endian) from first_bytes after MAGIC
    meta_len = struct.unpack('>I', first_bytes[len(MAGIC):len(MAGIC) + 4])[0]
    # Now read the full meta (meta_len bytes) -> total meta header size = 4 + meta_len
    meta_total_bytes = 4 + meta_len
    meta_total_bits = meta_total_bytes * 8
    meta_bits = read_bits_range(stego_path, len(MAGIC) * 8, meta_total_bits)
    meta_full = bits_to_bytes(meta_bits)
    # meta_full begins with 4-byte length followed by json
    meta, consumed = unpack_meta(meta_full)
    # meta should include payload_len
    payload_len = int(meta.get('payload_len', 0))
    if payload_len <= 0:
        # If payload_len missing, we fall back to reading remaining capacity and trim trailing zeros
        cap_bits = estimate_capacity_bits(stego_path)
        rest_bits = read_bits_range(stego_path, (len(MAGIC) + meta_total_bytes) * 8, cap_bits - (len(MAGIC) + meta_total_bytes) * 8)
        data = bits_to_bytes(rest_bits)
        return meta, data
    # Read payload_len bytes starting after MAGIC + meta_total_bytes
    payload_start_bit = (len(MAGIC) + meta_total_bytes) * 8
    payload_bits = read_bits_range(stego_path, payload_start_bit, payload_len * 8)
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
                # avoid overwrite: write a new name
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


# -------------------- Workers & Signals --------------------

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
                data = open(payload_path, 'rb').read()
                meta = {
                    'filename': os.path.basename(payload_path),
                    'index': t.get('index', 0),
                    'shards': t.get('shards', 1),
                    'mimetype': detect_mimetype(payload_path),
                }
                # compress
                if self.options.get('compress'):
                    data = zlib.compress(data)
                    meta['compressed'] = True
                else:
                    meta['compressed'] = False
                # encrypt
                if self.options.get('encrypt') and self.options.get('password'):
                    key, salt = derive_key(self.options.get('password'))
                    meta['salt'] = base64.b64encode(salt).decode('ascii')
                    f = Fernet(key)
                    data = f.encrypt(data)
                    meta['encrypted'] = True
                else:
                    meta['encrypted'] = False
                meta['payload_len'] = len(data)
                # hmac
                hkey = self.options.get('hmac_key') or (self.options.get('password') or 'hmac-salt').encode('utf-8')
                h = hmac.HMAC(hkey, hashes.SHA256(), backend=default_backend())
                h.update(data)
                mac = h.finalize()
                meta['hmac'] = base64.b64encode(mac).decode('ascii')
                payload = MAGIC + pack_meta(meta) + data
                # choose method
                if self.options.get('use_cs') and HAS_CS:
                    cs_key = base64.urlsafe_b64encode(b'module-' + (self.options.get('password') or '').encode('utf-8')).decode('ascii') if self.options.get('password') else 'nokey'
                    cs = CryptoSteganography(cs_key)
                    b64 = base64.b64encode(payload).decode('ascii')
                    cs.hide(carrier, out, b64)
                else:
                    embed_lsb(carrier, out, payload)
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
        for i, fpath in enumerate(self.files):
            try:
                if self.options.get('use_cs') and HAS_CS:
                    cs_key = base64.urlsafe_b64encode(b'module-' + (self.options.get('password') or '').encode('utf-8')).decode('ascii') if self.options.get('password') else 'nokey'
                    cs = CryptoSteganography(cs_key)
                    b64 = cs.retrieve(fpath)
                    payload = base64.b64decode(b64)
                    # with cs the entire payload is returned; parse directly
                    if not payload.startswith(MAGIC):
                        raise ValueError('No valid payload (magic mismatch)')
                    meta, hdr_len = unpack_meta(payload[len(MAGIC):])
                    data = payload[len(MAGIC) + hdr_len:]
                else:
                    meta, data = extract_payload_from_image(fpath)
                # verify hmac
                hkey = self.options.get('hmac_key') or (self.options.get('password') or 'hmac-salt').encode('utf-8')
                if 'hmac' in meta:
                    mac = base64.b64decode(meta['hmac'])
                    h = hmac.HMAC(hkey, hashes.SHA256(), backend=default_backend())
                    h.update(data)
                    try:
                        h.verify(mac)
                    except Exception:
                        raise ValueError('HMAC verification failed (data integrity)')
                # decrypt
                if meta.get('encrypted'):
                    salt = base64.b64decode(meta.get('salt')) if meta.get('salt') else None
                    password = self.options.get('password')
                    if not password:
                        raise ValueError('Encrypted payload requires password')
                    key, _ = derive_key(password, salt)
                    f = Fernet(key)
                    data = f.decrypt(data)
                # decompress
                if meta.get('compressed'):
                    data = zlib.decompress(data)
                out_name = meta.get('filename', 'extracted.bin')
                out_path = os.path.join(self.out_folder, out_name)
                base, ext = os.path.splitext(out_path)
                idx = 1
                while os.path.exists(out_path):
                    out_path = f"{base}_{idx}{ext}"
                    idx += 1
                with open(out_path, 'wb') as fh:
                    fh.write(data)
                self.signals.log.emit(f'Decoded -> {out_path}')
                # post-process open/move
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
                self.signals.log.emit(f'ERROR decoding {fpath}: {e}')
            self.signals.progress.emit(int((i + 1) / total * 100))
        self.signals.finished.emit()


# -------------------- GUI --------------------
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
        menu.addAction(preview_action)
        menu.addAction(remove_action)
        menu.exec(event.globalPos())

    def remove_selected(self):
        for it in self.selectedIndexes()[::-1]:
            self.takeItem(it.row())

    def preview_selected(self):
        items = [self.item(i).text() for i in range(self.count()) if self.item(i).isSelected()]
        if items:
            QMessageBox.information(self, 'Selected files', ''.join(items))


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Advanced Cryptosteganography v4')
        self.resize(1200, 780)
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
        self.mapping_combo.addItems(['One-to-one (by order)', 'Cycle payloads', 'Shard single payload across carriers'])
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
        self.decode_out = QLineEdit(os.getcwd())
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
        self.auto_open_exts = QLineEdit('.html,.htm,.py,.bat,.ps1,.sh,.mp3')
        prog_h.addWidget(self.auto_open_exts)
        main.addLayout(prog_h)

        progdir_h = QHBoxLayout()
        progdir_h.addWidget(QLabel('Programs folder:'))
        self.programs_dir_edit = QLineEdit(os.path.join(os.path.expanduser('~'), 'Programs'))
        progdir_h.addWidget(self.programs_dir_edit)
        btn_prog = QPushButton('Choose Programs Folder')
        btn_prog.clicked.connect(self.choose_programs_folder)
        progdir_h.addWidget(btn_prog)
        main.addLayout(progdir_h)

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

    def choose_programs_folder(self):
        d = QFileDialog.getExistingDirectory(self, 'Choose programs folder', self.programs_dir_edit.text())
        if d:
            self.programs_dir_edit.setText(d)

    def start_encode(self):
        carriers = [self.carrier_list.item(i).text() for i in range(self.carrier_list.count())]
        payloads = [self.payload_list.item(i).text() for i in range(self.payload_list.count())]
        if not carriers or not payloads:
            QMessageBox.warning(self, 'Missing', 'Add carrier(s) and payload(s)')
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

        options = {
            'compress': self.compress_cb.isChecked(),
            'encrypt': self.encrypt_cb.isChecked(),
            'password': self.password_edit.text() or None,
            'use_cs': self.use_cs_cb.isChecked(),
            'hmac_key': (self.password_edit.text() or 'hmac-salt').encode('utf-8')
        }
        self.encode_btn.setEnabled(False)
        worker = EncodeWorker(tasks, options)
        worker.signals.log.connect(self.log.addItem)
        worker.signals.progress.connect(self.encode_progress.setValue)
        worker.signals.finished.connect(self._encode_finished)
        self.pool.start(worker)

    def _encode_finished(self):
        self.encode_btn.setEnabled(True)
        self.log.addItem('Encode batch finished')

    def start_decode(self):
        files = [self.stego_list.item(i).text() for i in range(self.stego_list.count())]
        if not files:
            QMessageBox.warning(self, 'Missing', 'Add stego files')
            return
        out_folder = self.decode_out.text() or os.getcwd()
        auto_exts = {e.strip().lower() for e in self.auto_open_exts.text().split(',') if e.strip()}
        options = {
            'password': self.decode_pw.text() or None,
            'use_cs': self.use_cs_cb.isChecked() if hasattr(self, 'use_cs_cb') else False,
            'auto_open_all': self.auto_open_all_cb.isChecked(),
            'auto_open_exts': auto_exts,
            'move_to_programs': self.move_to_programs_cb.isChecked(),
            'programs_dir': self.programs_dir_edit.text(),
            'hmac_key': (self.decode_pw.text() or 'hmac-salt').encode('utf-8')
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


# -------------------- Main --------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
