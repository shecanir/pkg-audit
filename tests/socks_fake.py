"""A small SOCKS5 server (no authentication, CONNECT by name) for tests."""
import socket
import threading


def _pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _recvn(c, n):
    data = b""
    while len(data) < n:
        chunk = c.recv(n - len(data))
        if not chunk:
            raise OSError
        data += chunk
    return data


def serve(seen, mapping=None):
    """Listen on 127.0.0.1; `seen` collects the (host, port) asked for; `mapping` {host: (ip, port)}
    redirects a name, else the name is resolved normally. Returns (port, close)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=client, args=(c,), daemon=True).start()

    def client(c):
        try:
            ver, n = _recvn(c, 2)
            _recvn(c, n)
            c.sendall(b"\x05\x00")
            _, cmd, _, atyp = _recvn(c, 4)
            assert atyp == 3
            host = _recvn(c, _recvn(c, 1)[0]).decode()
            port = int.from_bytes(_recvn(c, 2), "big")
            seen.append((host, port))
            target = (mapping or {}).get(host, (host, port))
            try:
                up = socket.create_connection(target, 10)
            except OSError:
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
            _pipe(c, up)
        except (OSError, AssertionError):
            pass
        finally:
            c.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], srv.close
