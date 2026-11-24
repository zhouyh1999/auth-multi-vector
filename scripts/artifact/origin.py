"""Authenticated origin for the signed LoTTE manifests, restricted to the timing host."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import hmac,json,os,re,secrets,socket,ssl,subprocess,time
import argparse
METHODS=('raw','vida_per_token','vida_batched','block_fast')
SCOPES=('coarse','fine','rerank','all')
CERT_NAME='gem-owner.lotte.test'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    parser.add_argument("public", type=Path)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--peer", default="127.0.0.1")
    args = parser.parse_args()
    from common import ROOT as package, output
    ROOT = output(args.state.absolute().relative_to(package), 'results')
    os.umask(0o077)
    cert,key=ROOT/'source-v1.pem',ROOT/'source-v1.key'
    if not cert.exists() and not key.exists():
        conf=ROOT/'tls-source.cnf'
        conf.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=tls\n'
            '[dn]\nCN='+CERT_NAME+'\n[tls]\nbasicConstraints=critical,CA:TRUE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n'
            'subjectAltName=DNS:'+CERT_NAME+'\nsubjectKeyIdentifier=hash\n')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30',
            '-config',str(conf),'-keyout',str(key),'-out',str(cert)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    subprocess.run(['openssl','verify','-purpose','sslserver','-CAfile',str(cert),str(cert)],
        check=True,stdout=subprocess.DEVNULL)
    token=ROOT/'auth-token'
    if not token.exists():token.write_text(secrets.token_hex(32)+'\n')
    expected='Bearer '+token.read_text().strip()
    payload={f'/lotte-pooled-dev/{m}/{s}':(args.public/f'{m}.{s}.bin').read_bytes() for m in METHODS for s in SCOPES}
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    ctx.num_tickets=0
    ctx.load_cert_chain(cert,key)
    peer=socket.gethostbyname(args.peer)
    ip=socket.gethostbyname(args.bind)
    class Server(HTTPServer):
        allow_reuse_address=True
        def get_request(self):
            client,remote=super().get_request()
            try:
                if remote[0]!=peer:raise OSError('peer outside campaign')
                client.settimeout(8)
                return ctx.wrap_socket(client,server_side=True),remote
            except Exception:
                client.close()
                raise
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            visit=self.headers.get('X-Visit','')
            if not hmac.compare_digest(expected,self.headers.get('Authorization','')):
                self.send_error(403);return
            if self.path not in payload or not re.fullmatch('[0-9a-f]{32}',visit):
                self.send_error(404);return
            body=payload[self.path]
            self.send_response(200)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Content-Type','application/octet-stream')
            self.send_header('X-Visit',visit)
            self.send_header('Connection','close')
            self.end_headers()
            self.wfile.write(body);self.wfile.flush()
            _,_,method,scope=self.path.split('/')
            receipts.write(json.dumps(dict(id=visit,method=method,stage=scope,payload_bytes=len(body),utc=time.time(),
                tls=self.connection.version(),reused=self.connection.session_reused))+'\n')
    config=ROOT/'connection.json'
    port=int(json.loads(config.read_text())['address'].rsplit(':',1)[1]) if config.exists() else 0
    with (ROOT/'origin-receipts.jsonl').open('a',buffering=1) as receipts, Server((ip,port),Handler) as server:
        tmp=config.with_suffix('.tmp')
        tmp.write_text(json.dumps(dict(address=f'{ip}:{server.server_port}',tls_name=CERT_NAME,origin=ip,client=peer))+'\n')
        tmp.replace(config)
        (ROOT/'origin.pid').write_text(str(os.getpid())+'\n')
        server.timeout=2
        while not (ROOT/'stop-source').exists():server.handle_request()
if __name__=='__main__':main()

