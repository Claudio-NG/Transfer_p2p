import os
import sys
import ssl
import io
import csv
import json
import time
import asyncio
import hashlib
import struct
import uuid
import queue
import socket
import threading
import pathlib
import re as _re
from collections import deque
from dataclasses import dataclass
from typing import Optional, Callable, Dict, List, Tuple

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QSpinBox, QDoubleSpinBox, QProgressBar, QMessageBox, QTabWidget, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit, QGroupBox
)
from PyQt6.QtCore import Qt, QTimer, QMimeData
from PyQt6.QtGui import QPixmap

try:
    import qrcode
except Exception:
    qrcode = None

HEADER_LEN_SIZE = 8
CSV_PATH = os.path.abspath("./codigo_conexao.csv")

# =========================
#        HELPERS
# =========================

def pack_header(d: dict) -> bytes:
    b = json.dumps(d).encode("utf-8")
    return struct.pack("!Q", len(b)) + b

# ==== PATCH: read with timeout (evita sockets zumbis) ====
async def read_exact(reader: asyncio.StreamReader, n: int, timeout: float = 15.0) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)

async def read_header(reader: asyncio.StreamReader, timeout: float = 15.0) -> dict:
    l = struct.unpack("!Q", await read_exact(reader, HEADER_LEN_SIZE, timeout))[0]
    return json.loads((await read_exact(reader, l, timeout)).decode("utf-8"))

async def send_msg(writer: asyncio.StreamWriter, header: dict, payload: bytes = b"") -> None:
    writer.write(pack_header(header))
    if payload:
        writer.write(payload)
    await writer.drain()

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ceildiv(a: int, b: int) -> int:
    return (a + b - 1) // b

def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip

# ---- filename seguro
SAFE_FILENAME_RE = _re.compile(r"[^A-Za-z0-9 ._\-]")

def safe_filename(name: str) -> str:
    clean = pathlib.Path(name).name
    clean = SAFE_FILENAME_RE.sub("", clean)
    return clean or "arquivo"

# ---- CSV para persistir o código fixo
def save_code_csv(code: str, csv_path: str = CSV_PATH):
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["codigo"])
            w.writerow([code])
    except Exception:
        pass

def load_code_csv(csv_path: str = CSV_PATH) -> Optional[str]:
    try:
        if not os.path.exists(csv_path):
            return None
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            r = csv.reader(f)
            header = next(r, None)
            row = next(r, None)
            if row and row[0].strip():
                return row[0].strip()
    except Exception:
        pass
    return None

# =========================
#        SERVER CORE
# =========================

class TransferState:
    """Escreve em arquivo temporário .part, valida e renomeia no fim."""
    def __init__(self, final_path: str, file_size: int, chunk_size: int):
        self.final_path = final_path
        self.tmp_path = final_path + ".part"
        self.file_size = int(file_size)
        self.chunk_size = int(chunk_size)
        self.total_chunks = ceildiv(self.file_size, self.chunk_size)

        os.makedirs(os.path.dirname(self.final_path) or ".", exist_ok=True)
        self.fh = open(self.tmp_path, "wb+")
        self.fh.truncate(self.file_size)

        self.received = 0
        self.lock = asyncio.Lock()
        self.done = asyncio.Event()
        self.seen = set()

        # fsync em lote
        self._since_fsync = 0
        self._fsync_every = 64

    async def write_chunk(self, index: int, data: bytes):
        # valida índice/tamanho
        if index < 0 or index >= self.total_chunks:
            return
        if index != self.total_chunks - 1:
            if len(data) != self.chunk_size:
                return
        else:
            max_last = self.file_size - (index * self.chunk_size)
            if len(data) > max_last:
                return

        async with self.lock:
            if index in self.seen:
                return
            self.fh.seek(index * self.chunk_size)
            self.fh.write(data)
            self.seen.add(index)
            self.received += 1

            self._since_fsync += 1
            if self._since_fsync >= self._fsync_every or self.received >= self.total_chunks:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self._since_fsync = 0

            if self.received >= self.total_chunks:
                self.done.set()

    def flush_close(self):
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
        except Exception:
            pass
        try:
            self.fh.close()
        except Exception:
            pass

class ServerCore:
    """
    Usa 'expected_code' (código fixo definido pelo usuário) para autenticação.
    Garante integridade com SHA-256 final antes de renomear .part -> final.
    """
    def __init__(self, out_dir: str, expected_code: str, ssl_ctx=None, on_event: Optional[Callable[[str, dict], None]] = None):
        self.out_dir = out_dir
        self.expected_code = (expected_code or "").strip()
        self.ssl_ctx = ssl_ctx
        self.sessions: Dict[str, TransferState] = {}
        self.sessions_lock = asyncio.Lock()
        self.on_event = on_event
        self.meta: Dict[str, dict] = {}

    def emit(self, typ: str, data: dict):
        if self.on_event:
            try:
                self.on_event(typ, data)
            except Exception:
                pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            auth = await read_header(reader)
            # autenticação simples por código fixo
            if auth.get("type") != "auth" or (self.expected_code and auth.get("code") != self.expected_code):
                await send_msg(writer, {"type": "error", "reason": "auth"})
                writer.close()
                await writer.wait_closed()
                return

            manifest = await read_header(reader)
            if manifest.get("type") != "manifest":
                await send_msg(writer, {"type": "error", "reason": "manifest"})
                writer.close()
                await writer.wait_closed()
                return

            sess = manifest["session"]
            name = safe_filename(manifest["filename"])
            fsize = int(manifest["filesize"])
            csize = int(manifest["chunksize"])
            filehash = manifest.get("filehash")

            # valida manifesto
            if fsize <= 0 or csize < 512 * 1024 or csize > 64 * 1024 * 1024:
                await send_msg(writer, {"type": "error", "reason": "bad_manifest"})
                writer.close()
                await writer.wait_closed()
                return

            async with self.sessions_lock:
                st = self.sessions.get(sess)
                if not st:
                    final_path = os.path.join(self.out_dir, name)
                    st = TransferState(final_path, fsize, csize)
                    self.sessions[sess] = st
                    self.meta[sess] = {
                        "filename": name,
                        "filesize": fsize,
                        "chunksize": csize,
                        "filehash": filehash,
                    }
                    self.emit("session", {"session": sess, "filename": name, "total": st.total_chunks})

            await send_msg(writer, {"type": "ready", "session": sess, "chunks": st.total_chunks})

            while True:
                h = await read_header(reader)
                t = h.get("type")

                if t == "chunk":
                    sess2 = h.get("session")
                    if sess2 != sess:
                        await send_msg(writer, {"type": "error", "reason": "session"})
                        break
                    idx = int(h["index"])
                    size = int(h["size"])
                    hashexp = h["sha256"]
                    data = await read_exact(reader, size)
                    if sha256_bytes(data) != hashexp:
                        await send_msg(writer, {"type": "nack", "index": idx})
                        continue
                    await st.write_chunk(idx, data)
                    await send_msg(writer, {"type": "ack", "index": idx})
                    self.emit("progress", {"session": sess, "received": st.received, "total": st.total_chunks})

                elif t == "done":
                    meta = self.meta.get(sess, {})
                    expected = meta.get("filehash")
                    st.flush_close()
                    calc = sha256_file(st.tmp_path)
                    if expected and calc != expected:
                        try:
                            os.remove(st.tmp_path)
                        except Exception:
                            pass
                        await send_msg(writer, {"type": "error", "reason": "hash_mismatch"})
                    else:
                        try:
                            os.replace(st.tmp_path, st.final_path)
                        except Exception:
                            os.rename(st.tmp_path, st.final_path)
                        await send_msg(writer, {"type": "finished", "session": sess})
                        self.emit("finished", {"session": sess})
                    async with self.sessions_lock:
                        self.sessions.pop(sess, None)
                        self.meta.pop(sess, None)
                    break

                else:
                    await send_msg(writer, {"type": "error", "reason": "type"})

                if self.sessions.get(sess, None) and self.sessions[sess].done.is_set():
                    # cliente pode não mandar 'done'; finalize mesmo assim
                    meta = self.meta.get(sess, {})
                    expected = meta.get("filehash")
                    st.flush_close()
                    calc = sha256_file(st.tmp_path)
                    if expected and calc != expected:
                        try:
                            os.remove(st.tmp_path)
                        except Exception:
                            pass
                        await send_msg(writer, {"type": "error", "reason": "hash_mismatch"})
                    else:
                        try:
                            os.replace(st.tmp_path, st.final_path)
                        except Exception:
                            os.rename(st.tmp_path, st.final_path)
                        await send_msg(writer, {"type": "finished", "session": sess})
                        self.emit("finished", {"session": sess})
                    async with self.sessions_lock:
                        self.sessions.pop(sess, None)
                        self.meta.pop(sess, None)
                    break

        except asyncio.IncompleteReadError:
            pass
        except Exception:
            try:
                await send_msg(writer, {"type": "error", "reason": "exception"})
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def run_server(bind: str, port: int, server_inst: ServerCore, stop_event: Optional[asyncio.Event] = None):
    srv = await asyncio.start_server(server_inst.handle, bind, port, ssl=server_inst.ssl_ctx)
    server_inst.emit("listening", {"bind": bind, "port": port})
    async with srv:
        if stop_event is None:
            await srv.serve_forever()
        else:
            await stop_event.wait()
            srv.close()
            await srv.wait_closed()

# =========================
#        CLIENT CORE
# =========================

# ==== PATCH: worker resiliente ao handshake/queda ====
async def client_worker(host, port, code, manifest, q: asyncio.Queue, retries, max_retries,
                        on_progress: Optional[Callable[[int, int], None]],
                        ssl_ctx=None, cancel_event: Optional[asyncio.Event] = None):
    """
    Worker resiliente: reconecta se a conexão cair antes/depois do handshake e continua de onde parou.
    """

    async def open_stream():
        await asyncio.sleep(0.05)  # suaviza tempestade de reconexões paralelas
        return await asyncio.open_connection(
            host, port, ssl=ssl_ctx, server_hostname=host if ssl_ctx else None
        )

    reader = writer = None
    BACKOFFS = [0.2, 0.4, 0.8, 1.2, 2.0]  # s

    try:
        while True:
            if cancel_event and cancel_event.is_set():
                break

            # pega o próximo chunk
            try:
                idx = q.get_nowait()
            except asyncio.QueueEmpty:
                break

            # garante handshake ok
            alive = False
            for attempt in range(1, len(BACKOFFS) + 2):
                if cancel_event and cancel_event.is_set():
                    break
                try:
                    if reader is None or writer is None or writer.is_closing():
                        reader, writer = await open_stream()
                    await send_msg(writer, {"type": "auth", "code": code})
                    await send_msg(writer, {"type": "manifest", **manifest})
                    _ = await read_header(reader)  # espera "ready"
                    alive = True
                    break
                except (asyncio.IncompleteReadError, ConnectionResetError, OSError, asyncio.TimeoutError):
                    try:
                        if writer:
                            writer.close()
                            await writer.wait_closed()
                    except Exception:
                        pass
                    reader = writer = None
                    backoff = BACKOFFS[min(attempt - 1, len(BACKOFFS) - 1)]
                    await asyncio.sleep(backoff)

            if not alive:
                retries[idx] = retries.get(idx, 0) + 1
                if retries[idx] <= max_retries and not (cancel_event and cancel_event.is_set()):
                    await q.put(idx)
                continue

            # envia o chunk
            try:
                with open(manifest["filepath"], "rb") as f:
                    f.seek(idx * manifest["chunksize"])
                    data = f.read(manifest["chunksize"])
                hashexp = sha256_bytes(data)
                await send_msg(writer, {
                    "type": "chunk", "session": manifest["session"], "index": idx,
                    "size": len(data), "sha256": hashexp
                }, data)

                # espera ack/nack
                try:
                    ack = await read_header(reader, timeout=20.0)
                except (asyncio.IncompleteReadError, ConnectionResetError, OSError, asyncio.TimeoutError):
                    retries[idx] = retries.get(idx, 0) + 1
                    if retries[idx] <= max_retries and not (cancel_event and cancel_event.is_set()):
                        await q.put(idx)
                    try:
                        if writer:
                            writer.close()
                            await writer.wait_closed()
                    except Exception:
                        pass
                    reader = writer = None
                    continue

                if ack.get("type") == "ack" and ack.get("index") == idx:
                    if on_progress:
                        on_progress(len(data), manifest["filesize"])
                    continue

                # nack ou inesperado
                retries[idx] = retries.get(idx, 0) + 1
                if retries[idx] <= max_retries and not (cancel_event and cancel_event.is_set()):
                    await q.put(idx)

            except Exception:
                retries[idx] = retries.get(idx, 0) + 1
                if retries[idx] <= max_retries and not (cancel_event and cancel_event.is_set()):
                    await q.put(idx)
                try:
                    if writer:
                        writer.close()
                        await writer.wait_closed()
                except Exception:
                    pass
                reader = writer = None

        # finalização educada
        if not (cancel_event and cancel_event.is_set()):
            try:
                if reader is None or writer is None or writer.is_closing():
                    reader, writer = await open_stream()
                    await send_msg(writer, {"type": "auth", "code": code})
                    await send_msg(writer, {"type": "manifest", **manifest})
                    _ = await read_header(reader)
                await send_msg(writer, {"type": "done"})
                try:
                    _ = await read_header(reader)
                except Exception:
                    pass
            except Exception:
                pass
    finally:
        try:
            if writer:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass

async def client_send(host, port, code, file_path, chunk_mb, parallel,
                      on_progress=None, tls_ca=None, max_retries=3,
                      cancel_event: Optional[asyncio.Event] = None):
    chunk_size = int(float(chunk_mb) * 1024 * 1024)
    filesize = os.path.getsize(file_path)
    total_chunks = ceildiv(filesize, chunk_size)
    name = os.path.basename(file_path)
    sess = str(uuid.uuid4())
    filehash = sha256_file(file_path)
    manifest = {
        "type": "manifest",
        "session": sess,
        "filename": name,
        "filepath": file_path,
        "filesize": filesize,
        "chunksize": chunk_size,
        "total": total_chunks,
        "filehash": filehash,
    }
    q = asyncio.Queue()
    for i in range(total_chunks):
        await q.put(i)
    ssl_ctx = None
    if tls_ca:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls_ca)

    retries = {}
    parallel = max(1, int(parallel))
    tasks = []
    for _ in range(parallel):
        tasks.append(asyncio.create_task(
            client_worker(host, port, code, manifest, q, retries, max_retries, on_progress, ssl_ctx, cancel_event)
        ))
    await asyncio.gather(*tasks)

# =========================
#      THREAD WRAPPERS
# =========================

class ServerThread(threading.Thread):
    def __init__(self, bind, port, out_dir, code, q):
        super().__init__(daemon=True)
        self.bind = bind
        self.port = port
        self.out_dir = out_dir
        self.code = code
        self.q: queue.Queue = q
        self.loop = None
        self.stop_evt = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        def on_event(typ, data):
            self.q.put(("event", typ, data))
        srv = ServerCore(self.out_dir, self.code, None, on_event)
        self.stop_evt = asyncio.Event()
        try:
            self.loop.run_until_complete(run_server(self.bind, self.port, srv, self.stop_evt))
        finally:
            pass

    def stop(self):
        if self.loop and self.stop_evt:
            self.loop.call_soon_threadsafe(self.stop_evt.set)

class _ServerThreadWrapper(ServerThread):
    """Mesma funcionalidade do ServerThread, mantido para compatibilidade com ReceiverTab."""
    pass

# =========================
#         SENDER UI
# =========================

@dataclass
class QueueItem:
    path: str
    size: int
    status: str = "Pendente"   # Pendente | Enviando | Concluído | Cancelado | Erro
    sent_bytes: int = 0
    rate_mbps: float = 0.0
    eta_str: str = "--"

class SendQueueManager:
    """Gerencia a fila de envios e o ciclo de vida do envio corrente."""
    def __init__(self, on_update: Callable[[], None]):
        self.items: List[QueueItem] = []
        self.on_update = on_update
        self.thread: Optional[threading.Thread] = None
        self.cancel_flag = threading.Event()
        self.running = False
        # Estatísticas do arquivo corrente
        self.total = 0
        self.sent = 0
        self.last_sent = 0
        self.last_time = time.time()
        self.rate_window = deque(maxlen=20)  # ~4s se tick=200ms
        self.current_target: Optional[QueueItem] = None
        # Parâmetros dinâmicos
        self.host = ""
        self.port = 4433
        self.code = ""
        self.chunk_mb = 4.0
        self.parallel = 4

    def add_file(self, path: str):
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        self.items.append(QueueItem(path=path, size=size))
        self.on_update()

    def clear_completed(self):
        self.items = [it for it in self.items if it.status not in ("Concluído", "Cancelado")]
        self.on_update()

    def _progress_cb(self, delta: int, total: int):
        self.sent += delta
        if self.current_target:
            self.current_target.sent_bytes = self.sent

    def _run_one(self, item: QueueItem):
        """Executa um envio de arquivo (bloco síncrono dentro de uma thread)."""
        self.cancel_flag.clear()
        self.total = item.size
        self.sent = 0
        self.last_sent = 0
        self.last_time = time.time()
        self.rate_window.clear()

        def runner():
            # roda client_send em um loop asyncio isolado
            cancel_event = asyncio.Event()

            def watch_cancel():
                # espelha cancel_flag (threading) no cancel_event (asyncio)
                while not cancel_event.is_set():
                    if self.cancel_flag.is_set():
                        try:
                            loop.call_soon_threadsafe(cancel_event.set)
                        except Exception:
                            break
                    time.sleep(0.05)

            nonlocal_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(nonlocal_loop)
            loop = nonlocal_loop

            watcher = threading.Thread(target=watch_cancel, daemon=True)
            watcher.start()

            try:
                loop.run_until_complete(
                    client_send(
                        self.host, self.port, self.code,
                        item.path, self.chunk_mb, self.parallel,
                        on_progress=self._progress_cb,
                        tls_ca=None, max_retries=3,
                        cancel_event=cancel_event
                    )
                )
            finally:
                try:
                    loop.stop()
                except Exception:
                    pass
                try:
                    loop.close()
                except Exception:
                    pass

        t = threading.Thread(target=runner, daemon=True)
        t.start()
        # Espera terminar (ou cancelar)
        while t.is_alive():
            if self.cancel_flag.is_set():
                break
            time.sleep(0.1)
        t.join(timeout=0.1)

    def start(self, host: str, port: int, code: str, chunk_mb: float, parallel: int):
        if self.running:
            return
        self.host, self.port, self.code = host, int(port), code
        self.chunk_mb, self.parallel = float(chunk_mb), int(parallel)
        self.running = True

        def main_loop():
            try:
                for item in self.items:
                    if item.status in ("Concluído", "Enviando"):
                        continue
                    item.status = "Enviando"
                    self.current_target = item
                    self.on_update()
                    try:
                        self._run_one(item)
                        if self.cancel_flag.is_set():
                            item.status = "Cancelado"
                        else:
                            item.status = "Concluído"
                    except Exception:
                        item.status = "Erro"
                    finally:
                        self.current_target = None
                        self.on_update()
                    if self.cancel_flag.is_set():
                        break
            finally:
                self.running = False
                self.cancel_flag.clear()
                self.on_update()

        self.thread = threading.Thread(target=main_loop, daemon=True)
        self.thread.start()

    def cancel_current(self):
        if self.running:
            self.cancel_flag.set()

    # ======= estatística/ETA ========
    def tick_stats(self) -> Tuple[float, str]:
        """Atualiza taxa média móvel e ETA do item corrente; retorna (mbps, eta_str)."""
        if not self.current_target or self.total <= 0:
            return 0.0, "--"
        now = time.time()
        dt = now - self.last_time
        if dt <= 0:
            return self.current_target.rate_mbps, self.current_target.eta_str

        delta = self.sent - self.last_sent
        inst_rate = (delta / dt) / (1024 * 1024)  # MB/s
        self.rate_window.append(inst_rate)
        avg_rate = sum(self.rate_window) / max(1, len(self.rate_window))  # MB/s
        self.last_sent = self.sent
        self.last_time = now

        restante = max(0, self.total - self.sent)
        if avg_rate > 0:
            eta_sec = restante / (avg_rate * 1024 * 1024)  # segundos
            m, s = int(eta_sec // 60), int(eta_sec % 60)
            eta_str = f"{m}m {s}s"
        else:
            eta_str = "--"

        self.current_target.rate_mbps = avg_rate
        self.current_target.eta_str = eta_str
        return avg_rate, eta_str

class SenderTab(QWidget):
    def __init__(self):
        super().__init__()
        self.queue_mgr = SendQueueManager(on_update=self.refresh_table)
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.setup_ui()

    # ---------- UI ----------
    def setup_ui(self):
        lay = QVBoxLayout()

        grid = QGridLayout()
        grid.addWidget(QLabel("Código de conexão"), 0, 0)
        self.ed_code = QLineEdit()
        # Tenta pré-carregar apenas o "código" salvo
        saved = load_code_csv()
        # Dica de formato: p2p://host:port#codigo
        placeholder = "p2p://192.168.0.10:4433#SEU-CODIGO"
        self.ed_code.setPlaceholderText(placeholder)
        grid.addWidget(self.ed_code, 0, 1, 1, 3)

        grid.addWidget(QLabel("Chunk (MB)"), 1, 0)
        self.ed_chunk = QDoubleSpinBox()
        self.ed_chunk.setDecimals(1)
        self.ed_chunk.setRange(0.5, 64.0)
        self.ed_chunk.setValue(4.0)
        grid.addWidget(self.ed_chunk, 1, 1)

        grid.addWidget(QLabel("Paralelo"), 1, 2)
        self.ed_par = QSpinBox()
        self.ed_par.setRange(1, 16)
        self.ed_par.setValue(4)
        grid.addWidget(self.ed_par, 1, 3)

        # controles da fila
        hl = QHBoxLayout()
        self.bt_add = QPushButton("Adicionar arquivo")
        self.bt_add.clicked.connect(self.pick_file)
        self.bt_start = QPushButton("Iniciar fila")
        self.bt_start.clicked.connect(self.start_queue)
        self.bt_cancel = QPushButton("Cancelar atual")
        self.bt_cancel.clicked.connect(self.cancel_current)
        self.bt_clear = QPushButton("Limpar concluídos")
        self.bt_clear.clicked.connect(self.clear_completed)

        hl.addWidget(self.bt_add)
        hl.addWidget(self.bt_start)
        hl.addWidget(self.bt_cancel)
        hl.addWidget(self.bt_clear)

        # tabela da fila
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Arquivo", "Tamanho", "Status", "Progresso", "Velocidade", "ETA"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        # barra de progresso e labels
        self.pb = QProgressBar()
        self.pb.setRange(0, 1000)
        self.lb_rate = QLabel("0.00 MB/s (média)")
        self.lb_eta = QLabel("Restante: --")

        lay.addLayout(grid)
        lay.addLayout(hl)
        lay.addWidget(self.table)
        lay.addWidget(self.pb)
        hl2 = QHBoxLayout()
        hl2.addWidget(self.lb_rate)
        hl2.addStretch(1)
        hl2.addWidget(self.lb_eta)
        lay.addLayout(hl2)
        self.setLayout(lay)

        # drag & drop simples (arrastar arquivos)
        self.setAcceptDrops(True)

    # drag & drop handlers
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        md: QMimeData = event.mimeData()
        for url in md.urls():
            path = url.toLocalFile()
            if path and os.path.isfile(path):
                self.queue_mgr.add_file(path)
        self.refresh_table()

    def pick_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Escolher arquivo(s)", "", "Todos (*.*)")
        for f in files:
            self.queue_mgr.add_file(f)
        self.refresh_table()

    # código p2p://host:port#codigo
    def parse_code(self, code):
        c = code.strip()
        if c.startswith("p2p://"):
            c = c[6:]
        code_fixed = None
        if "#" in c:
            hostport, code_fixed = c.split("#", 1)
        else:
            parts = c.replace(" ", "#").split("#")
            if len(parts) == 2:
                hostport, code_fixed = parts
            else:
                hostport = c
        if ":" in hostport:
            host, port = hostport.split(":", 1)
            port = int(port)
        else:
            host, port = hostport, 4433
        if not code_fixed or code_fixed.strip() == "":
            return None
        return host.strip(), int(port), code_fixed.strip()

    def start_queue(self):
        parsed = self.parse_code(self.ed_code.text())
        if not parsed:
            QMessageBox.warning(self, "Erro", "Código de conexão inválido. Use p2p://host:port#CODIGO")
            return
        host, port, code = parsed

        # salva o código no CSV (somente o código fixo)
        try:
            save_code_csv(code)
        except Exception:
            pass

        if not self.queue_mgr.items:
            QMessageBox.information(self, "Fila vazia", "Adicione arquivos antes de iniciar.")
            return
        self.queue_mgr.start(host, port, code, float(self.ed_chunk.value()), int(self.ed_par.value()))
        self.timer.start(200)  # atualização periódica

    def cancel_current(self):
        self.queue_mgr.cancel_current()

    def clear_completed(self):
        self.queue_mgr.clear_completed()

    # ---------- atualizações de UI ----------
    def refresh_table(self):
        self.table.setRowCount(len(self.queue_mgr.items))
        for i, it in enumerate(self.queue_mgr.items):
            name = os.path.basename(it.path)
            size_mb = f"{it.size / (1024*1024):.2f} MB"
            prog = f"{(it.sent_bytes / it.size * 100.0) if it.size else 0.0:.1f}%"
            rate = f"{it.rate_mbps:.2f} MB/s"
            eta = it.eta_str

            self.table.setItem(i, 0, QTableWidgetItem(name))
            self.table.setItem(i, 1, QTableWidgetItem(size_mb))
            self.table.setItem(i, 2, QTableWidgetItem(it.status))
            self.table.setItem(i, 3, QTableWidgetItem(prog))
            self.table.setItem(i, 4, QTableWidgetItem(rate))
            self.table.setItem(i, 5, QTableWidgetItem(eta))

    def tick(self):
        # atualiza progresso do atual
        ct = self.queue_mgr.current_target
        if ct and ct.size > 0:
            pct = int(ct.sent_bytes / ct.size * 1000)
            self.pb.setValue(min(pct, 1000))
            avg_rate, eta_str = self.queue_mgr.tick_stats()
            self.lb_rate.setText(f"{avg_rate:.2f} MB/s (média)")
            self.lb_eta.setText(f"Restante: {eta_str}")
        else:
            if not self.queue_mgr.running:
                self.pb.setValue(0)
                self.lb_rate.setText("0.00 MB/s (média)")
                self.lb_eta.setText("Restante: --")
                self.timer.stop()
        self.refresh_table()

# =========================
#        RECEIVER UI
# =========================

class ReceiverTab(QWidget):
    def __init__(self):
        super().__init__()
        self.thread: Optional[_ServerThreadWrapper] = None
        self.rows = {}
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self._running = False  # estado do servidor (para toggle)
        self.setup_ui()

    def setup_ui(self):
        lay = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel("Porta"), 0, 0)
        self.ed_port = QSpinBox()
        self.ed_port.setRange(1, 65535)
        self.ed_port.setValue(4433)
        grid.addWidget(self.ed_port, 0, 1, 1, 2)

        grid.addWidget(QLabel("Código (fixo)"), 1, 0)
        self.ed_code = QLineEdit()
        # carregar código salvo
        saved = load_code_csv()
        if saved:
            self.ed_code.setText(saved)
        grid.addWidget(self.ed_code, 1, 1, 1, 2)

        grid.addWidget(QLabel("Saída"), 2, 0)
        self.ed_out = QLineEdit(os.path.abspath("./recebidos"))
        self.bt_out = QPushButton("Escolher")
        self.bt_out.clicked.connect(self.pick_out)
        grid.addWidget(self.ed_out, 2, 1)
        grid.addWidget(self.bt_out, 2, 2)

        hl = QHBoxLayout()
        self.bt_toggle = QPushButton("Iniciar")  # único botão INICIAR/PARAR
        self.bt_toggle.clicked.connect(self.toggle_server)
        hl.addWidget(self.bt_toggle)

        self.gb_code = QGroupBox("Código de conexão (URL para o remetente)")
        v2 = QVBoxLayout()
        self.lb_code_url = QLabel("-")
        v2.addWidget(self.lb_code_url)
        self.bt_copy = QPushButton("Copiar código (URL)")
        self.bt_copy.clicked.connect(self.copy_code)
        v2.addWidget(self.bt_copy, alignment=Qt.AlignmentFlag.AlignLeft)
        self.lb_qr = QLabel()
        v2.addWidget(self.lb_qr, alignment=Qt.AlignmentFlag.AlignLeft)
        self.gb_code.setLayout(v2)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Sessão", "Arquivo", "Recebidos", "Total", "%"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        lay.addLayout(grid)
        lay.addLayout(hl)
        lay.addWidget(self.gb_code)
        lay.addWidget(self.table)
        lay.addWidget(QLabel("Log"))
        lay.addWidget(self.log)
        self.setLayout(lay)

    def build_code_url(self):
        ip = local_ip()
        port = int(self.ed_port.value())
        code = self.ed_code.text().strip()
        return f"p2p://{ip}:{port}#{"{code}".format(code=code) if code else ''}".rstrip("#")

    def update_code_ui(self):
        url = self.build_code_url()
        self.lb_code_url.setText(url or "-")
        if qrcode and url:
            img = qrcode.make(url)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            pix = QPixmap()
            pix.loadFromData(buf.getvalue())
            self.lb_qr.setPixmap(pix)
        else:
            self.lb_qr.setPixmap(QPixmap())

    def pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Escolher pasta de saída", self.ed_out.text().strip() or ".")
        if d:
            self.ed_out.setText(d)

    def toggle_server(self):
        if not self._running:
            # Iniciar
            port = int(self.ed_port.value())
            code = self.ed_code.text().strip()
            out_dir = self.ed_out.text().strip()
            if not code:
                QMessageBox.warning(self, "Erro", "Informe o código fixo.")
                return
            os.makedirs(out_dir, exist_ok=True)
            # salva código no CSV
            save_code_csv(code)
            q = queue.Queue()
            self.thread = _ServerThreadWrapper("0.0.0.0", port, out_dir, code, q)
            self.thread.start()
            self._running = True
            self.bt_toggle.setText("Parar")
            self.append_log(f"Servidor iniciado em 0.0.0.0:{port}")
            self.update_code_ui()
            self.timer.start(200)
        else:
            # Parar
            if self.thread:
                self.thread.stop()
            self.bt_toggle.setEnabled(False)  # desabilita até confirmar parada
            self.append_log("Encerrando servidor...")

    def append_log(self, txt: str):
        self.log.appendPlainText(txt)

    def copy_code(self):
        QApplication.clipboard().setText(self.build_code_url() or "")

    def tick(self):
        # quando thread realmente parar, faça o toggle voltar
        if self.thread and not self.thread.is_alive() and self._running:
            self._running = False
            self.bt_toggle.setText("Iniciar")
            self.bt_toggle.setEnabled(True)
            self.timer.stop()
            self.append_log("Servidor parado")

        if not self.thread:
            return

        while True:
            try:
                typ, ev, data = self.thread.q.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break
            if typ != "event":
                continue
            if ev == "listening":
                self.append_log(f"Escutando em {data['bind']}:{data['port']}")
            elif ev == "session":
                sess = data["session"]
                name = data["filename"]
                total = data["total"]
                row = getattr(self.thread, "rows", {}).get(sess) if hasattr(self.thread, "rows") else None
                if row is None:
                    if not hasattr(self.thread, "rows"):
                        self.thread.rows = {}
                        self.thread.table_rows = 0
                    row = self.thread.table_rows
                    self.thread.table_rows += 1
                    self.table.insertRow(row)
                    self.thread.rows[sess] = row
                self.table.setItem(row, 0, QTableWidgetItem(sess))
                self.table.setItem(row, 1, QTableWidgetItem(name))
                self.table.setItem(row, 2, QTableWidgetItem("0"))
                self.table.setItem(row, 3, QTableWidgetItem(str(total)))
                self.table.setItem(row, 4, QTableWidgetItem("0.0"))
                self.append_log(f"Sessão {sess} arquivo {name} total {total}")
            elif ev == "progress":
                sess = data["session"]
                rec = data["received"]
                tot = data["total"]
                row = getattr(self.thread, "rows", {}).get(sess) if hasattr(self.thread, "rows") else None
                if row is None:
                    continue
                self.table.setItem(row, 2, QTableWidgetItem(str(rec)))
                self.table.setItem(row, 3, QTableWidgetItem(str(tot)))
                pct = 0.0
                if tot > 0:
                    pct = rec * 100.0 / tot
                self.table.setItem(row, 4, QTableWidgetItem(f"{pct:.1f}"))
            elif ev == "finished":
                sess = data["session"]
                row = getattr(self.thread, "rows", {}).get(sess) if hasattr(self.thread, "rows") else None
                if row is not None:
                    self.table.setItem(row, 4, QTableWidgetItem("100.0"))
                # hashing final no receptor (apenas logar quando terminar)
                try:
                    file_name = self.table.item(row, 1).text() if row is not None else None
                    if file_name:
                        out_path = os.path.join(self.ed_out.text().strip(), file_name)
                        if os.path.exists(out_path):
                            h = sha256_file(out_path)
                            self.append_log(f"Sessão {sess} finalizada | SHA256={h}")
                        else:
                            self.append_log(f"Sessão {sess} finalizada")
                    else:
                        self.append_log(f"Sessão {sess} finalizada")
                except Exception:
                    self.append_log(f"Sessão {sess} finalizada")

# =========================
#          MAIN
# =========================

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Transfer P2P")
        self.resize(960, 720)
        tabs = QTabWidget()
        tabs.addTab(SenderTab(), "ENVIAR")
        tabs.addTab(ReceiverTab(), "RECEBER")
        lay = QVBoxLayout()
        lay.addWidget(tabs)
        self.setLayout(lay)
        self.apply_style()

    def apply_style(self):
        self.setStyleSheet("""
            QWidget { font-family: Segoe UI, Arial; font-size: 12pt; }
            QPushButton { padding: 8px 14px; border-radius: 12px; background: #0a2a66; color: #fff; }
            QPushButton:disabled { background: #8aa1c4; }
            QLineEdit, QSpinBox, QDoubleSpinBox, QPlainTextEdit { padding: 6px; border: 1px solid #c7d2e8; border-radius: 10px; }
            QProgressBar { border: 1px solid #c7d2e8; border-radius: 10px; text-align: center; }
            QGroupBox { border: 1px solid #c7d2e8; border-radius: 10px; margin-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QTableWidget { border: 1px solid #c7d2e8; border-radius: 10px; }
        """)

def run_gui():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_gui()