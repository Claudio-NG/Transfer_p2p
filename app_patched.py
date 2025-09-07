import os
import sys
import ssl
import io
import json
import time
import asyncio
import hashlib
import struct
import uuid
import secrets
import socket
import threading
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QSpinBox, QDoubleSpinBox, QProgressBar, QMessageBox, QTabWidget, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit, QGroupBox
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
import queue
try:
    import qrcode
except ImportError:
    qrcode = None
    
HEADER_LEN_SIZE = 8


def pack_header(d):
    b = json.dumps(d).encode("utf-8")
    return struct.pack("!Q", len(b)) + b

async def read_exact(reader, n):
    return await reader.readexactly(n)

async def read_header(reader):
    l = struct.unpack("!Q", await read_exact(reader, HEADER_LEN_SIZE))[0]
    return json.loads((await read_exact(reader, l)).decode("utf-8"))

async def send_msg(writer, header, payload=b""):
    writer.write(pack_header(header))
    if payload:
        writer.write(payload)
    await writer.drain()

def sha256_bytes(b):
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def ceildiv(a, b):
    return (a + b - 1) // b

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip

class TransferState:
    def __init__(self, path, file_size, chunk_size):
        self.path = path
        self.file_size = file_size
        self.chunk_size = chunk_size
        self.total_chunks = ceildiv(file_size, chunk_size)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.fh = open(path, "wb+")
        self.fh.truncate(file_size)
        self.received = 0
        self.lock = asyncio.Lock()
        self.done = asyncio.Event()
        self.seen = set()

    async def write_chunk(self, index, data):
        async with self.lock:
            if index in self.seen:
                return
            self.fh.seek(index * self.chunk_size)
            self.fh.write(data)
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.seen.add(index)
            self.received += 1
            if self.received >= self.total_chunks:
                self.done.set()

    def close(self):
        try:
            self.fh.close()
        except:
            pass

class ServerCore:
    def __init__(self, out_dir, token, ssl_ctx=None, on_event=None):
        self.out_dir = out_dir
        self.token = token
        self.ssl_ctx = ssl_ctx
        self.sessions = {}
        self.sessions_lock = asyncio.Lock()
        self.on_event = on_event

    def emit(self, typ, data):
        if self.on_event:
            try:
                self.on_event(typ, data)
            except:
                pass

    async def handle(self, reader, writer):
        try:
            auth = await read_header(reader)
            if auth.get("type") != "auth" or auth.get("token") != self.token:
                await send_msg(writer, {"type":"error","reason":"auth"})
                writer.close()
                await writer.wait_closed()
                return
            manifest = await read_header(reader)
            if manifest.get("type") != "manifest":
                await send_msg(writer, {"type":"error","reason":"manifest"})
                writer.close()
                await writer.wait_closed()
                return
            sess = manifest["session"]
            name = manifest["filename"]
            fsize = manifest["filesize"]
            csize = manifest["chunksize"]
            async with self.sessions_lock:
                st = self.sessions.get(sess)
                if not st:
                    path = os.path.join(self.out_dir, name)
                    st = TransferState(path, fsize, csize)
                    self.sessions[sess] = st
                    self.emit("session", {"session":sess,"filename":name,"total":st.total_chunks})
            await send_msg(writer, {"type":"ready","session":sess,"chunks":st.total_chunks})
            while True:
                h = await read_header(reader)
                t = h.get("type")
                if t == "chunk":
                    sess2 = h["session"]
                    if sess2 != sess:
                        await send_msg(writer, {"type":"error","reason":"session"})
                        break
                    idx = h["index"]
                    size = h["size"]
                    hashexp = h["sha256"]
                    data = await read_exact(reader, size)
                    if sha256_bytes(data) != hashexp:
                        await send_msg(writer, {"type":"nack","index":idx})
                        continue
                    await st.write_chunk(idx, data)
                    await send_msg(writer, {"type":"ack","index":idx})
                    self.emit("progress", {"session":sess,"received":st.received,"total":st.total_chunks})
                elif t == "done":
                    if st.done.is_set():
                        await send_msg(writer, {"type":"finished","session":sess})
                        self.emit("finished", {"session":sess})
                    else:
                        await send_msg(writer, {"type":"pending","left":st.total_chunks - st.received})
                else:
                    await send_msg(writer, {"type":"error","reason":"type"})
                if st.done.is_set():
                    await send_msg(writer, {"type":"finished","session":sess})
                    self.emit("finished", {"session":sess})
                    break
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            try:
                await send_msg(writer, {"type":"error","reason":"exception"})
            except:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

async def run_server(bind, port, server_inst, stop_event=None):
    srv = await asyncio.start_server(server_inst.handle, bind, port, ssl=server_inst.ssl_ctx)
    server_inst.emit("listening", {"bind":bind,"port":port})
    async with srv:
        if stop_event is None:
            await srv.serve_forever()
        else:
            await stop_event.wait()
            srv.close()
            await srv.wait_closed()

async def client_worker(host, port, token, manifest, q, retries, max_retries, on_progress, ssl_ctx=None):
    r, w = await asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if ssl_ctx else None)
    await send_msg(w, {"type":"auth","token":token})
    await send_msg(w, {"type":"manifest", **manifest})
    await read_header(r)
    f = open(manifest["filepath"], "rb")
    try:
        while True:
            try:
                idx = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            f.seek(idx * manifest["chunksize"])
            data = f.read(manifest["chunksize"])
            hashexp = sha256_bytes(data)
            await send_msg(w, {"type":"chunk","session":manifest["session"],"index":idx,"size":len(data),"sha256":hashexp}, data)
            try:
                ack = await read_header(r)
            except asyncio.IncompleteReadError:
                retries[idx] = retries.get(idx,0) + 1
                if retries[idx] <= max_retries:
                    await q.put(idx)
                continue
            if ack.get("type") == "ack" and ack.get("index") == idx:
                if on_progress:
                    on_progress(len(data), manifest["filesize"])
                continue
            if ack.get("type") == "nack" and ack.get("index") == idx:
                retries[idx] = retries.get(idx,0) + 1
                if retries[idx] <= max_retries:
                    await q.put(idx)
                continue
            retries[idx] = retries.get(idx,0) + 1
            if retries[idx] <= max_retries:
                await q.put(idx)
        await send_msg(w, {"type":"done"})
        try:
            await read_header(r)
        except asyncio.IncompleteReadError:
            pass
    finally:
        try:
            f.close()
        except:
            pass
        try:
            w.close()
            await w.wait_closed()
        except:
            pass

async def client_send(host, port, token, file_path, chunk_mb, parallel, on_progress=None, tls_ca=None, max_retries=3):
    chunk_size = int(float(chunk_mb) * 1024 * 1024)
    filesize = os.path.getsize(file_path)
    total_chunks = ceildiv(filesize, chunk_size)
    name = os.path.basename(file_path)
    sess = str(uuid.uuid4())
    manifest = {"type":"manifest","session":sess,"filename":name,"filepath":file_path,"filesize":filesize,"chunksize":chunk_size,"total":total_chunks}
    q = asyncio.Queue()
    for i in range(total_chunks):
        await q.put(i)
    ssl_ctx = None
    if tls_ca:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls_ca)
    retries = {}
    if parallel < 1:
        parallel = 1
    tasks = []
    for _ in range(parallel):
        tasks.append(asyncio.create_task(client_worker(host, port, token, manifest, q, retries, max_retries, on_progress, ssl_ctx)))
    await asyncio.gather(*tasks)

class ServerThread(threading.Thread):
    def __init__(self, bind, port, out_dir, token, q):
        super().__init__(daemon=True)
        self.bind = bind
        self.port = port
        self.out_dir = out_dir
        self.token = token
        self.q = q
        self.loop = None
        self.stop_evt = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        def on_event(typ, data):
            self.q.put(("event", typ, data))
        srv = ServerCore(self.out_dir, self.token, None, on_event)
        self.stop_evt = asyncio.Event()
        try:
            self.loop.run_until_complete(run_server(self.bind, self.port, srv, self.stop_evt))
        finally:
            pass

    def stop(self):
        if self.loop and self.stop_evt:
            self.loop.call_soon_threadsafe(self.stop_evt.set)

class SenderTab(QWidget):
    def __init__(self):
        super().__init__()
        self.total = 0
        self.sent = 0
        self.last_sent = 0
        self.last_time = time.time()
        self.thread = None
        self.setup_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)

    def setup_ui(self):
        lay = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel("Código de conexão"), 0, 0)
        self.ed_code = QLineEdit()
        grid.addWidget(self.ed_code, 0, 1, 1, 2)
        grid.addWidget(QLabel("Arquivo"), 1, 0)
        self.ed_file = QLineEdit()
        self.bt_browse = QPushButton("Escolher")
        self.bt_browse.clicked.connect(self.pick_file)
        grid.addWidget(self.ed_file, 1, 1)
        grid.addWidget(self.bt_browse, 1, 2)
        grid.addWidget(QLabel("Chunk (MB)"), 2, 0)
        self.ed_chunk = QDoubleSpinBox()
        self.ed_chunk.setDecimals(1)
        self.ed_chunk.setRange(0.5, 64.0)
        self.ed_chunk.setValue(4.0)
        grid.addWidget(self.ed_chunk, 2, 1, 1, 2)
        grid.addWidget(QLabel("Paralelo"), 3, 0)
        self.ed_par = QSpinBox()
        self.ed_par.setRange(1, 16)
        self.ed_par.setValue(4)
        grid.addWidget(self.ed_par, 3, 1, 1, 2)
        self.bt_send = QPushButton("Enviar")
        self.bt_send.clicked.connect(self.start_send)
        self.pb = QProgressBar()
        self.pb.setRange(0, 1000)
        self.lb_rate = QLabel("0 MB/s")
        lay.addLayout(grid)
        lay.addWidget(self.bt_send)
        lay.addWidget(self.pb)
        lay.addWidget(self.lb_rate, alignment=Qt.AlignmentFlag.AlignRight)
        self.setLayout(lay)

    def pick_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Escolher arquivo", "", "Todos (*.*)")
        if f:
            self.ed_file.setText(f)

    def parse_code(self, code):
        c = code.strip()
        if c.startswith("p2p://"):
            c = c[6:]
        token = None
        if "#" in c:
            hostport, token = c.split("#", 1)
        else:
            parts = c.replace(" ", "#").split("#")
            if len(parts) == 2:
                hostport, token = parts
            else:
                hostport = c
        if ":" in hostport:
            host, port = hostport.split(":", 1)
            port = int(port)
        else:
            host, port = hostport, 4433
        if not token or token.strip() == "":
            return None
        return host.strip(), int(port), token.strip()

    def start_send(self):
        parsed = self.parse_code(self.ed_code.text())
        if not parsed:
            QMessageBox.warning(self, "Erro", "Código de conexão inválido")
            return
        host, port, token = parsed
        file_path = self.ed_file.text().strip()
        if not os.path.isfile(file_path):
            QMessageBox.warning(self, "Erro", "Arquivo inválido")
            return
        self.total = os.path.getsize(file_path)
        self.sent = 0
        self.last_sent = 0
        self.last_time = time.time()
        self.bt_send.setEnabled(False)
        chunk_mb = float(self.ed_chunk.value())
        parallel = int(self.ed_par.value())
        self.thread = threading.Thread(target=self.run_send, args=(host, port, token, file_path, chunk_mb, parallel))
        self.thread.daemon = True
        self.thread.start()
        self.timer.start(200)

    def run_send(self, host, port, token, file_path, chunk_mb, parallel):
        def on_prog(delta, total):
            self.sent += delta
        asyncio.run(client_send(host, port, token, file_path, chunk_mb, parallel, on_prog, None, 3))

    def tick(self):
        if self.total > 0:
            pct = int(self.sent / self.total * 1000)
            if pct > 1000:
                pct = 1000
            self.pb.setValue(pct)
            now = time.time()
            dt = now - self.last_time
            if dt > 0:
                rate = (self.sent - self.last_sent) / dt / (1024*1024)
                self.lb_rate.setText(f"{rate:.2f} MB/s")
                self.last_sent = self.sent
                self.last_time = now
        if self.thread and not self.thread.is_alive():
            self.bt_send.setEnabled(True)
            self.timer.stop()

class ReceiverTab(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.events = asyncio.Queue()
        self.rows = {}
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.token = secrets.token_hex(16)
        self.setup_ui()

    def setup_ui(self):
        lay = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel("Porta"), 0, 0)
        self.ed_port = QSpinBox()
        self.ed_port.setRange(1, 65535)
        self.ed_port.setValue(4433)
        grid.addWidget(self.ed_port, 0, 1, 1, 2)
        grid.addWidget(QLabel("Token"), 1, 0)
        self.ed_token = QLineEdit(self.token)
        grid.addWidget(self.ed_token, 1, 1, 1, 2)
        grid.addWidget(QLabel("Saída"), 2, 0)
        self.ed_out = QLineEdit(os.path.abspath("./recebidos"))
        self.bt_out = QPushButton("Escolher")
        self.bt_out.clicked.connect(self.pick_out)
        grid.addWidget(self.ed_out, 2, 1)
        grid.addWidget(self.bt_out, 2, 2)
        hl = QHBoxLayout()
        self.bt_start = QPushButton("Iniciar")
        self.bt_stop = QPushButton("Parar")
        self.bt_stop.setEnabled(False)
        self.bt_start.clicked.connect(self.start_server)
        self.bt_stop.clicked.connect(self.stop_server)
        hl.addWidget(self.bt_start)
        hl.addWidget(self.bt_stop)
        self.gb_code = QGroupBox("Código de conexão")
        v2 = QVBoxLayout()
        self.lb_code = QLabel("-")
        v2.addWidget(self.lb_code)
        self.bt_copy = QPushButton("Copiar código")
        self.bt_copy.clicked.connect(self.copy_code)
        v2.addWidget(self.bt_copy, alignment=Qt.AlignmentFlag.AlignLeft)
        self.lb_qr = QLabel()
        v2.addWidget(self.lb_qr, alignment=Qt.AlignmentFlag.AlignLeft)
        self.gb_code.setLayout(v2)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Sessão","Arquivo","Recebidos","Total","%"])
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

    def build_code(self):
        ip = local_ip()
        port = int(self.ed_port.value())
        token = self.ed_token.text().strip()
        return f"p2p://{ip}:{port}#{token}"

    def update_code_ui(self):
        code = self.build_code()
        self.lb_code.setText(code)
        if qrcode:
            img = qrcode.make(code)
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

    def start_server(self):
        port = int(self.ed_port.value())
        token = self.ed_token.text().strip()
        out_dir = self.ed_out.text().strip()
        if not token:
            QMessageBox.warning(self, "Erro", "Informe o token")
            return
        os.makedirs(out_dir, exist_ok=True)
        q = queue.Queue()
        self.thread = _ServerThreadWrapper("0.0.0.0", port, out_dir, token, q)
        self.thread.start()
        self.bt_start.setEnabled(False)
        self.bt_stop.setEnabled(True)
        self.append_log(f"Servidor iniciado em 0.0.0.0:{port}")
        self.update_code_ui()
        self.timer.start(200)

    def stop_server(self):
        if self.thread:
            self.thread.stop()
        self.bt_stop.setEnabled(False)
        self.append_log("Encerrando servidor...")

    def append_log(self, txt):
        self.log.appendPlainText(txt)

    def copy_code(self):
        QApplication.clipboard().setText(self.build_code())

    def tick(self):
        if self.thread and not self.thread.is_alive():
            self.bt_start.setEnabled(True)
            self.bt_stop.setEnabled(False)
            self.timer.stop()
            self.append_log("Servidor parado")
        if not self.thread:
            return
        while True:
            try:
                typ, ev, data = self.thread.q.get_nowait()
            except:
                break
            if typ != "event":
                continue
            if ev == "listening":
                self.append_log(f"Escutando em {data['bind']}:{data['port']}")
            elif ev == "session":
                sess = data["session"]
                name = data["filename"]
                total = data["total"]
                row = self.thread.rows.get(sess)
                if row is None:
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
                row = self.thread.rows.get(sess)
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
                row = self.thread.rows.get(sess)
                if row is not None:
                    self.table.setItem(row, 4, QTableWidgetItem("100.0"))
                self.append_log(f"Sessão {sess} finalizada")

class _ServerThreadWrapper(threading.Thread):
    def __init__(self, bind, port, out_dir, token, q):
        super().__init__(daemon=True)
        self.bind = bind
        self.port = port
        self.out_dir = out_dir
        self.token = token
        self.q = q
        self.loop = None
        self.stop_evt = None
        self.rows = {}
        self.table_rows = 0

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        def on_event(typ, data):
            self.q.put(("event", typ, data))
        srv = ServerCore(self.out_dir, self.token, None, on_event)
        self.stop_evt = asyncio.Event()
        try:
            self.loop.run_until_complete(run_server(self.bind, self.port, srv, self.stop_evt))
        finally:
            pass

    def stop(self):
        if self.loop and self.stop_evt:
            self.loop.call_soon_threadsafe(self.stop_evt.set)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Transfer P2P")
        self.resize(860, 640)
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