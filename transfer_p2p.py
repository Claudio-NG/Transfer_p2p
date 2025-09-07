import os
import ssl
import json
import argparse
import asyncio
import hashlib
import struct
import uuid

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

class Server:
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
    if server_inst.on_event:
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

def build_ssl_server(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile=keyfile)
    return ctx

def parse_args():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("server")
    s1.add_argument("--bind", default="0.0.0.0")
    s1.add_argument("--port", type=int, default=4433)
    s1.add_argument("--out", required=True)
    s1.add_argument("--token", required=True)
    s1.add_argument("--tls-cert")
    s1.add_argument("--tls-key")
    s2 = sub.add_parser("send")
    s2.add_argument("--host", required=True)
    s2.add_argument("--port", type=int, default=4433)
    s2.add_argument("--file", required=True)
    s2.add_argument("--chunk", type=float, default=4.0)
    s2.add_argument("--parallel", type=int, default=4)
    s2.add_argument("--token", required=True)
    s2.add_argument("--tls-ca")
    s2.add_argument("--retries", type=int, default=3)
    return p.parse_args()

def cli_main():
    args = parse_args()
    if args.cmd == "server":
        ssl_ctx = None
        if args.tls_cert and args.tls_key:
            ssl_ctx = build_ssl_server(args.tls_cert, args.tls_key)
        srv = Server(args.out, args.token, ssl_ctx, None)
        asyncio.run(run_server(args.bind, args.port, srv, None))
    else:
        asyncio.run(client_send(args.host, args.port, args.token, args.file, args.chunk, args.parallel, None, args.tls_ca, args.retries))

if __name__ == "__main__":
    cli_main()