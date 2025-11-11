#!/usr/bin/env python3
"""
Micro Burp – HTTP proxy + fuzzer
Uso: python micro_burp.py <host> <porta> <porta_escuta>
Ex: python micro_burp.py alvo.com 80 8080
Navegue em http://localhost:8080
No console: i nome_param wordlist.txt
"""
import asyncio, sys, socket, re, gzip, io, logging
from urllib.parse import parse_qs, urlencode

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Configurações
MAX_LINE = 64 * 1024
TIMEOUT = 5

def parse_request(head):
    lines = head.decode().splitlines()
    method, path, _ = lines[0].split(' ', 2)
    hdr = {l.split(': ', 1)[0]: l.split(': ', 1)[1] for l in lines[1:] if ': ' in l}
    return method.upper(), path, hdr

def fix_len(head, body):
    return re.sub(rb'\r\nContent-Length: \d+', b'\r\nContent-Length: ' + str(len(body)).encode(), head, flags=re.I)

async def recv_headers(reader):
    buf = b''
    while True:
        data = await reader.read(MAX_LINE)
        if not data: return None, None
        buf += data
        if b'\r\n\r\n' in buf:
            head, _, body = buf.partition(b'\r\n\r\n')
            return head + b'\r\n\r\n', body

async def recv_response(reader, head):
    cl = int(re.search(rb'Content-Length: (\d+)', head, re.I).group(1) or 0)
    body = b''
    while len(body) < cl:
        data = await reader.read(MAX_LINE)
        if not data: break
        body += data
    if b'chunked' in head.lower():
        body = dechunk(body)
    if b'gzip' in head.lower():
        body = gzip.decompress(body)
    return head, body

def dechunk(data):
    out = b''
    while data:
        size, _, data = data.partition(b'\r\n')
        chunk_size = int(size, 16)
        out += data[:chunk_size]
        data = data[chunk_size + 2:]
    return out

async def shoot(method, path, head, body, param, payload, host, port):
    try:
        if method == 'GET':
            q = parse_qs(path.split('?', 1)[1]) if '?' in path else {}
            q[param] = payload
            new_path = path.split('?')[0] + '?' + urlencode(q, doseq=True)
            new_body = body
        else:
            q = parse_qs(body.decode()) if body else {}
            q[param] = payload
            new_body = urlencode(q, doseq=True).encode()
            head = fix_len(head, new_body)
            new_path = path

        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b'%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n%s' %
                     (method.encode(), new_path.encode(), host.encode(),
                      head.split(b'\r\n\r\n', 1)[0].split(b'\r\n', 1)[1], new_body))
        await writer.drain()
        resp_head, resp_body = await recv_response(reader, await recv_headers(reader))
        writer.close()
        await writer.wait_closed()
        status = resp_head.split()[1]
        size = len(resp_body)
        logging.info(f'[fuzz] {payload[:30]} -> {status} {size}')
    except Exception as e:
        logging.error(f'[fuzz error] {payload[:30]}: {e}')

async def intruder(method, path, head, body, param, wlist, host, port):
    tasks = [shoot(method, path, head, body, param, p, host, port) for p in wlist]
    await asyncio.gather(*tasks)

async def handle_client(reader, writer, host, port):
    try:
        head, body = await recv_headers(reader)
        if not head:
            writer.close()
            await writer.wait_closed()
            return
        method, path, hdr = parse_request(head)
        logging.info(f'[>] {method} {path}')

        # Comando via stdin (simplificado)
        if sys.stdin.readable() and not sys.stdin.buffer.peek(1):  # Verifica se há input
            cmd = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            cmd = cmd.strip()
            if cmd.startswith('i '):
                _, param, file = cmd.split()
                with open(file) as f:
                    wlist = f.read().splitlines()
                await intruder(method, path, head, body, param, wlist, host, port)
                writer.close()
                await writer.wait_closed()
                return

        # Encaminhar
        srv_reader, srv_writer = await asyncio.open_connection(host, port)
        srv_writer.write(fix_len(head, body) + body)
        await srv_writer.drain()
        resp_head, resp_body = await recv_response(srv_reader, await recv_headers(srv_reader))
        srv_writer.close()
        await srv_writer.wait_closed()
        writer.write(resp_head + resp_body)
        await writer.drain()
    except Exception as e:
        logging.error(f'[client error]: {e}')
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    if len(sys.argv) != 4:
        sys.exit("Uso: python micro_burp.py <host> <porta> <porta_escuta>")
    host, port, listen = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, host, port), '0.0.0.0', listen)
    logging.info(f'[*] Proxy http://localhost:{listen} -> {host}:{port}')
    logging.info('[*] Comando: i param wordlist.txt')
    await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())

