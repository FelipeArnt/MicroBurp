#!/usr/bin/env python3

# |----|LABELO/VSW|----|@author:FelipeArnt|----|
# PocketBurp - Ferramenta para Ensaios Funcionais de Segurança Cibernética.
# O script foi baseado no BurpSuite, focando nas funções de captura de tráfego e envio de payloads. [PROXY e INTRUDER]

import asyncio, sys, socket, re, gzip, io, logging, argparse
from urllib.parse import parse_qs, urlencode, urlparse
import ssl

try:
    import aioconsole #aioconsole
except ImportError:
    aioconsole = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

MAX_LINE = 64 * 1024
TIMEOUT = 5
RATE_LIMIT = 10
 # Classe do servidor proxy e suas funções...
class ProxyServer:
    def __init__(self, host, port, listen, bind='0.0.0.0'):
        self.host, self.port, self.listen, self.bind = host, port, listen, bind
        self.connections = {}
        self.sem = asyncio.Semaphore(RATE_LIMIT)

    # Utilizando async para que as funções sejam pausadas e retomadas por certas condições...
    async def get_connection(self, host, port, ssl=False): # Função para realizar a conexao;
        key = (host, port, ssl)
        if key in self.connections:
            reader, writer = self.connections[key]
            if not writer.is_closing():
                return reader, writer
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl)
        self.connections[key] = (reader, writer)
        return reader, writer

    # Recebe os headers e armazena em um array...
    async def recv_headers(self, reader):
        lines = []
        while True:
            line = await reader.readuntil(b'\r\n')
            if line == b'\r\n':
                break
            lines.append(line.decode().strip())
        head = '\r\n'.join(lines) + '\r\n\r\n'
        return head.encode()

    
    # Recebe o body e armazena em um array...
    async def recv_body(self, reader, head):
        cl = int(re.search(rb'Content-Length: (\d+)', head, re.I).group(1) or 0)
        body = await reader.readexactly(cl) if cl else b''
        if b'chunked' in head.lower():
            body = self.dechunk(body)
        if b'gzip' in head.lower():
            body = gzip.decompress(body)
        return body

    def dechunk(self, data):
        out = b''
        while data:
            size, _, data = data.partition(b'\r\n')
            chunk_size = int(size, 16)
            out += data[:chunk_size]
            data = data[chunk_size + 2:]
        return out
    # handler da conexao
    async def handle_connect(self, reader, writer, path):
        try:
            host, port = path.split(':')
            port = int(port)
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            tun_reader, tun_writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
            await asyncio.gather(
                self.tunnel(reader, tun_writer),
                self.tunnel(tun_reader, writer)
            )
        except Exception as e:
            logging.exception(f'[CONNECT error]: {e}')
        finally:
            writer.close()
            await writer.wait_closed()

    async def tunnel(self, reader, writer):
        try:
            while True:
                data = await reader.read(MAX_LINE)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    # Disparador
    async def shoot(self, method, path, head, body, param, payload, filters):
        async with self.sem:
            try:
                new_path = path.replace(f'§{param}§', payload)
                new_head = head.replace(f'§{param}§'.encode(), payload.encode())
                new_body = body.replace(f'§{param}§'.encode(), payload.encode())
                if method in ('GET', 'POST') and '§' not in new_path and '§' not in new_body.decode():
                    if method == 'GET':
                        q = parse_qs(urlparse(new_path).query)
                        q[param] = payload
                        new_path = new_path.split('?')[0] + '?' + urlencode(q, doseq=True)
                    else:
                        q = parse_qs(new_body.decode())
                        q[param] = payload
                        new_body = urlencode(q, doseq=True).encode()

                reader, writer = await self.get_connection(self.host, self.port, ssl=self.port == 443)
                writer.write(b'%s %s HTTP/1.1\r\n%s\r\n%s' % (method.encode(), new_path.encode(), new_head, new_body))
                await writer.drain()
                resp_head = await self.recv_headers(reader)
                resp_body = await self.recv_body(reader, resp_head)
                status = int(resp_head.split()[1])
                size = len(resp_body)

                match = True
                if 'status' in filters and status != int(filters['status']):
                    match = False
                if 'size' in filters and not eval(f'{size}{filters["size"]}'):
                    match = False
                if 'regex' in filters and not re.search(filters['regex'], resp_body.decode(), re.I):
                    match = False

                if match:
                    logging.info(f'[fuzz hit] {payload[:30]} -> {status} {size}b')
            except Exception as e:
                logging.exception(f'[fuzz error] {payload[:30]}: {e}')

    # INTRUDER...
    async def intruder(self, method, path, head, body, param, wlist, filters):
        tasks = [self.shoot(method, path, head, body, param, p, filters) for p in wlist]
        await asyncio.gather(*tasks)

    # handler do cliente...
    async def handle_client(self, reader, writer):
        try:
            head = await self.recv_headers(reader)
            if not head:
                return
            lines = head.decode().splitlines()
            method, path, _ = lines[0].split(' ', 2)
            if method.upper() == 'CONNECT':
                await self.handle_connect(reader, writer, path)
                return
            body = await self.recv_body(reader, head)
            logging.info(f'[>] {method} {path}')

            reader_srv, writer_srv = await self.get_connection(self.host, self.port, ssl=self.port == 443)
            writer_srv.write(head + body)
            await writer_srv.drain()
            resp_head = await self.recv_headers(reader_srv)
            resp_body = await self.recv_body(reader_srv, resp_head)
            writer.write(resp_head + resp_body)
            await writer.drain()
        except Exception as e:
            logging.exception(f'[client error]: {e}')
        finally:
            writer.close()
            await writer.wait_closed()

    async def command_loop(self):
        if not aioconsole:
            logging.warning("aioconsole não instalado; comandos stdin desabilitados")
            return
        while True:
            try:
                cmd = await aioconsole.ainput('')
                cmd = cmd.strip()
                if cmd.startswith('i '):
                    parts = cmd.split()
                    param, file = parts[1], parts[2]
                    filters = {}
                    for f in parts[3:]:
                        if '=' in f:
                            k, v = f.split('=', 1)
                            filters[k] = v
                    with open(file) as f:
                        wlist = f.read().splitlines()
                    method, path, head, body = 'GET', '/?§param§=test', b'Host: example.com\r\n\r\n', b''
                    await self.intruder(method, path, head, body, param, wlist, filters)
            except Exception as e:
                logging.exception(f'[cmd error]: {e}')

    # Função run utilizando await e com registro de logs...
    async def run(self):
        server = await asyncio.start_server(self.handle_client, self.bind, self.listen)
        logging.info(f'[*] Proxy http://localhost:{self.listen} -> {self.host}:{self.port}')
        logging.info('[*] Comando: i param wordlist.txt [status=200 size>1000 regex=error]')
        await asyncio.gather(server.serve_forever(), self.command_loop())

# Main
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('port', type=int)
    parser.add_argument('listen', type=int)
    parser.add_argument('--bind', default='0.0.0.0')
    args = parser.parse_args()
    proxy = ProxyServer(args.host, args.port, args.listen, args.bind)
    asyncio.run(proxy.run())

if __name__ == '__main__':
    main()
