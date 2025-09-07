import sys
import os
import time
import threading
import asyncio
from queue import Queue, Empty
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QSpinBox, QDoubleSpinBox, QProgressBar, QMessageBox, QTabWidget, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit
from PyQt6.QtCore import Qt, QTimer
from transfer_p2p import client_send, Server, run_server, build_ssl_server

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
        grid.addWidget(QLabel("Host"), 0, 0)
        self.ed_host = QLineEdit("127.0.0.1")
        grid.addWidget(self.ed_host, 0, 1, 1, 2)
        grid.addWidget(QLabel("Porta"), 1, 0)
        self.ed_port = QSpinBox()
        self.ed_port.setRange(1, 65535)
        self.ed_port.setValue(4433)
        grid.addWidget(self.ed_port, 1, 1, 1, 2)
        grid.addWidget(QLabel("Token"), 2, 0)
        self.ed_token = QLineEdit()
        grid.addWidget(self.ed_token, 2, 1, 1, 2)
        grid.addWidget(QLabel("Arquivo"), 3, 0)
        self.ed_file = QLineEdit()
        self.bt_browse = QPushButton("Escolher")
        self.bt_browse.clicked.connect(self.pick_file)
        grid.addWidget(self.ed_file, 3, 1)
        grid.addWidget(self.bt_browse, 3, 2)
        grid.addWidget(QLabel("Chunk (MB)"), 4, 0)
        self.ed_chunk = QDoubleSpinBox()
        self.ed_chunk.setDecimals(1)
        self.ed_chunk.setRange(0.5, 64.0)
        self.ed_chunk.setValue(4.0)
        grid.addWidget(self.ed_chunk, 4, 1, 1, 2)
        grid.addWidget(QLabel("Paralelo"), 5, 0)
        self.ed_par = QSpinBox()
        self.ed_par.setRange(1, 16)
        self.ed_par.setValue(4)
        grid.addWidget(self.ed_par, 5, 1, 1, 2)
        grid.addWidget(QLabel("TLS CA (opcional)"), 6, 0)
        self.ed_ca = QLineEdit()
        grid.addWidget(self.ed_ca, 6, 1, 1, 2)
        grid.addWidget(QLabel("Tentativas"), 7, 0)
        self.ed_retries = QSpinBox()
        self.ed_retries.setRange(0, 10)
        self.ed_retries.setValue(3)
        grid.addWidget(self.ed_retries, 7, 1, 1, 2)
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

    def start_send(self):
        host = self.ed_host.text().strip()
        port = int(self.ed_port.value())
        token = self.ed_token.text().strip()
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
        ca = self.ed_ca.text().strip() or None
        retries = int(self.ed_retries.value())
        self.thread = threading.Thread(target=self.run_send, args=(host, port, token, file_path, chunk_mb, parallel, ca, retries))
        self.thread.daemon = True
        self.thread.start()
        self.timer.start(200)

    def run_send(self, host, port, token, file_path, chunk_mb, parallel, ca, retries):
        def on_prog(delta, total):
            self.sent += delta
        asyncio.run(client_send(host, port, token, file_path, chunk_mb, parallel, on_prog, ca, retries))

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

class ServerThread(threading.Thread):
    def __init__(self, bind, port, out_dir, token, cert, key, q):
        super().__init__(daemon=True)
        self.bind = bind
        self.port = port
        self.out_dir = out_dir
        self.token = token
        self.cert = cert
        self.key = key
        self.q = q
        self.loop = None
        self.stop_evt = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        ssl_ctx = None
        if self.cert and self.key:
            ssl_ctx = build_ssl_server(self.cert, self.key)
        def on_event(typ, data):
            self.q.put(("event", typ, data))
        srv = Server(self.out_dir, self.token, ssl_ctx, on_event)
        self.stop_evt = asyncio.Event()
        try:
            self.loop.run_until_complete(run_server(self.bind, self.port, srv, self.stop_evt))
        finally:
            pass

    def stop(self):
        if self.loop and self.stop_evt:
            self.loop.call_soon_threadsafe(self.stop_evt.set)

class ReceiverTab(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.events = Queue()
        self.rows = {}
        self.setup_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)

    def setup_ui(self):
        lay = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel("Bind"), 0, 0)
        self.ed_bind = QLineEdit("0.0.0.0")
        grid.addWidget(self.ed_bind, 0, 1, 1, 2)
        grid.addWidget(QLabel("Porta"), 1, 0)
        self.ed_port = QSpinBox()
        self.ed_port.setRange(1, 65535)
        self.ed_port.setValue(4433)
        grid.addWidget(self.ed_port, 1, 1, 1, 2)
        grid.addWidget(QLabel("Token"), 2, 0)
        self.ed_token = QLineEdit()
        grid.addWidget(self.ed_token, 2, 1, 1, 2)
        grid.addWidget(QLabel("Saída"), 3, 0)
        self.ed_out = QLineEdit(os.path.abspath("./recebidos"))
        self.bt_out = QPushButton("Escolher")
        self.bt_out.clicked.connect(self.pick_out)
        grid.addWidget(self.ed_out, 3, 1)
        grid.addWidget(self.bt_out, 3, 2)
        grid.addWidget(QLabel("TLS Cert"), 4, 0)
        self.ed_cert = QLineEdit()
        grid.addWidget(self.ed_cert, 4, 1)
        self.bt_cert = QPushButton("Escolher")
        self.bt_cert.clicked.connect(self.pick_cert)
        grid.addWidget(self.bt_cert, 4, 2)
        grid.addWidget(QLabel("TLS Key"), 5, 0)
        self.ed_key = QLineEdit()
        grid.addWidget(self.ed_key, 5, 1)
        self.bt_key = QPushButton("Escolher")
        self.bt_key.clicked.connect(self.pick_key)
        grid.addWidget(self.bt_key, 5, 2)
        hl = QHBoxLayout()
        self.bt_start = QPushButton("Iniciar")
        self.bt_stop = QPushButton("Parar")
        self.bt_stop.setEnabled(False)
        self.bt_start.clicked.connect(self.start_server)
        self.bt_stop.clicked.connect(self.stop_server)
        hl.addWidget(self.bt_start)
        hl.addWidget(self.bt_stop)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Sessão","Arquivo","Recebidos","Total","%"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        lay.addLayout(grid)
        lay.addLayout(hl)
        lay.addWidget(self.table)
        lay.addWidget(QLabel("Log"))
        lay.addWidget(self.log)
        self.setLayout(lay)

    def pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Escolher pasta de saída", self.ed_out.text().strip() or ".")
        if d:
            self.ed_out.setText(d)

    def pick_cert(self):
        f, _ = QFileDialog.getOpenFileName(self, "Escolher certificado", "", "Certificados (*.crt *.pem);;Todos (*.*)")
        if f:
            self.ed_cert.setText(f)

    def pick_key(self):
        f, _ = QFileDialog.getOpenFileName(self, "Escolher chave", "", "Chaves (*.key *.pem);;Todos (*.*)")
        if f:
            self.ed_key.setText(f)

    def start_server(self):
        bind = self.ed_bind.text().strip()
        port = int(self.ed_port.value())
        token = self.ed_token.text().strip()
        out_dir = self.ed_out.text().strip()
        cert = self.ed_cert.text().strip() or None
        key = self.ed_key.text().strip() or None
        if not token:
            QMessageBox.warning(self, "Erro", "Informe o token")
            return
        os.makedirs(out_dir, exist_ok=True)
        self.thread = ServerThread(bind, port, out_dir, token, cert, key, self.events)
        self.thread.start()
        self.bt_start.setEnabled(False)
        self.bt_stop.setEnabled(True)
        self.timer.start(200)
        self.append_log(f"Servidor iniciado em {bind}:{port}")

    def stop_server(self):
        if self.thread:
            self.thread.stop()
        self.bt_stop.setEnabled(False)
        self.append_log("Encerrando servidor...")

    def append_log(self, txt):
        self.log.appendPlainText(txt)

    def tick(self):
        if self.thread and not self.thread.is_alive():
            self.bt_start.setEnabled(True)
            self.bt_stop.setEnabled(False)
            self.timer.stop()
            self.append_log("Servidor parado")
        while True:
            try:
                typ, ev, data = self.events.get_nowait()
            except Empty:
                break
            if typ != "event":
                continue
            if ev == "listening":
                self.append_log(f"Escutando em {data['bind']}:{data['port']}")
            elif ev == "session":
                sess = data["session"]
                name = data["filename"]
                total = data["total"]
                row = self.rows.get(sess)
                if row is None:
                    row = self.table.rowCount()
                    self.table.insertRow(row)
                    self.rows[sess] = row
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
                row = self.rows.get(sess)
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
                row = self.rows.get(sess)
                if row is not None:
                    self.table.setItem(row, 4, QTableWidgetItem("100.0"))
                self.append_log(f"Sessão {sess} finalizada")

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Transfer P2P")
        self.resize(800, 600)
        tabs = QTabWidget()
        tabs.addTab(SenderTab(), "SEND")
        tabs.addTab(ReceiverTab(), "RECEIVE")
        lay = QVBoxLayout()
        lay.addWidget(tabs)
        self.setLayout(lay)

def run_gui():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
