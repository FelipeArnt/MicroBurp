#!/usr/bin/env python3

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
            except Exception as e:
                logging.exception(f'[fuzz error] {payload[:30]}: {e}')

    # INTRUDER...
    async def intruder(self, method, path, head, body, param, wlist, filters):
        tasks = [self.shoot(method, path, head, body, param, p, filters) for p in wlist]
        await asyncio.gather(*tasks)

    # handler do cliente...
    async def handle_client(self, reader, writer):
        try:
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
