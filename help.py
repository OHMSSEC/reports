import argparse
import ctypes
import json
import logging
import multiprocessing
import os
import socket
import sys
import urllib
from datetime import datetime
from urllib.error import URLError
from urllib.request import urlopen

import dns.query
import dns.resolver
import dns.zone
import pyfiglet
import requests


class Scan:
    def __init__(self, domain, ports, timeout, key):

        self.domain = domain
        self.ports = ports
        self.timeout = timeout
        self.key = key
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter('\033[93m''[%(levelname)s] %(asctime)s %(message)s',
                                      datefmt='%m/%d/%Y %I:%M:%S %p''\033[32m', )

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)

        self.logger.addHandler(ch)
        fh = logging.FileHandler(f"{datetime.today().strftime('%A, %B %d, %Y')}.log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        self.logger.addHandler(fh)

    def ip_api(self):
        """ """
        try:

            fields = {'{query}': self.domain}
            req = requests.get(url="http://ip-api.com/json/", params=fields, timeout=10)
            resp = req.json()
            for c, i in resp.items():
                self.logger.warning(f"{c.capitalize()} | {i}")
            self.logger.info(f"\n\t {req.headers['Date']}")
        except requests.exceptions.RequestException:
            ...

    def top_1(self):

        # global s #AttributeError: 'socket' object has no attribute 'brute_force'
        for port in self.ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                s.settimeout(self.timeout)

                if s.connect_ex((self.domain, port)) == 0:
                    """s.send(f' HEAD / HTTP/1.1\r\n Host:{self.domain}\r\n' 'Connection: keep-alive\r\n' 'Accept: 
                    */*\r\n' 'Accept-Encoding: gzip, deflate\r\n' 'Accept-Language: en-US,en;q=0.5\r\n' f'Referer: 
                    http://{self.domain}/\r\n' 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) 
                    Gecko/20100101 Firefox/98.0'.encode( 'UTF-8')) """
                    s.send('0x02'.encode('ascii', 'ignore'))
                    banner = s.recv(1024)

                    self.logger.info(
                        '\033[32m'f"[PORT]  [OPEN]   | {port} | {socket.getservbyport(port).upper()} | {banner} |")

                else:
                    self.logger.debug(
                        '\033[1;31m'f"[PORT]  [CLOSE/DROP/FILTERED] | {port} | {socket.getservbyport(port).upper()} |")

            except OSError:
                continue
            except KeyboardInterrupt:
                sys.exit(1)

    def dns_python3(self):
        """ """

        print('\t\t[+] DNS = Resolving . . .\n')
        try:
            for regexs in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SOA','CAA', 'RP','SRV', 'SPF','DNAME', 'HINFO']:
                # 'NS', 'TXT', 'CAA', ' RP', 'SOA', 'SRV', 'PTR', 'SPF', 'DNAME':

                resp = dns.resolver.query(self.domain, regexs, raise_on_no_answer=False)

                if resp.rrset is not None:
                    out = (str(resp.rrset))
                    # if re.match(r'\\all\s+', out):
                    self.logger.warning(out)

        except dns.resolver.NoAnswer:
            self.logger.debug('\033[41m'"[!]ERRO[!]The DNS response does not contain an answer to the question: {} IN "
                              "NS"'\033[0;0m\n''\033[1m'.format(self.domain))
        except KeyboardInterrupt:
            sys.exit(1)
        except KeyError:
            pass

    def dns_xfr(self):
        """___"""
        registrons = dns.resolver.query(self.domain, "NS")
        lista = []

        for registro in registrons:
            lista.append(str(registro))
        for registro in lista:
            try:

                transfzona = dns.zone.from_xfr(dns.query.xfr(registro, self.domain))


            except dns.exception.FormError:
                self.logger.debug('\033[41m'"[!]ERRO[!] No answer or RRset not for qname:"'\033[0;0m\n''\033[1m')
                ...
            except dns.resolver.NoAnswer:
                self.logger.debug(
                    f"'\033[41m'[!]ERRO[!]The DNS response does not contain an answer to the question: NS'\033["
                    f"0;0m\n''\033[1m'")
                ...
            except dns.exception.SyntaxError:
                ...
            except ValueError:
                ...
            except dns.resolver.NXDOMAIN:
                self.logger.error(F"None of DNS query names exist: {self.domain}")
                ...
            except EOFError:
                ...
            except KeyboardInterrupt:
                sys.exit(1)
            else:

                self.logger.critical('\033[43m'"[+]Tranferência de Zona Realizada[+]"'\033[0;0m''\033[1m')
                registroDNS = transfzona.nodes.keys()

                for n in registroDNS:
                    print(transfzona[n].to_text(n), "\n")

    def brute_force(self):

        """ """

        self.logger.info('\t\t[+] Inciando Força Bruta ...\n')

        if os.name == 'nt':

            caminho = "C:\\Users\\ohms\\OneDrive\\Área de Trabalho\\Estudo\\data\\manual\\best-dns-wordlist.txt"
        else:
            caminho = '/mnt/c/Users/ohmsl/OneDrive/Área de Trabalho/Estudo/data/manual/best-dns-wordlist.txt'

        with open(caminho) as arquivo:
            sub = arquivo.readlines()
        for dnse in sub:
            force = dnse.strip("\n") + "." + self.domain
            try:

                self.logger.info(F"{force} | {socket.gethostbyname(force)}")
            except socket.gaierror:
                ...
            except KeyboardInterrupt:
                sys.exit(1)

    def email_hunter(self):
        """API Hunter.io """
        print("'\033[1m'\t[+] Possiveis Emails ...\t\n")
        try:

            req = urlopen(
                f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={self.key}")
            "https://api.hunter.io/v2/domain-search?domain={}&api_key=6a5b4fa748e6bbe572c5470f0f44d92c78ff59aa"

            rjson = json.load(req)
            # print(rjson['data']['emails'][0])

            for item in rjson['data']['emails']:
                for chave, valor in item.items():
                    print(chave.capitalize(), "\t|\t", valor)

        except urllib.error.URLError:

            self.logger.error("[!] APi expirada requisiçoes execedidas visite => https://hunter.io")
        except IndexError:
            self.logger.error("[!] Informe o argumento")


if __name__ == '__main__':
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    ascii_banner = pyfiglet.figlet_format("\t\tOHMS[SEC]\t")
    print('\033[94m' + ascii_banner + '\033[94m')

    parse = argparse.ArgumentParser(description="[i]")
    parse.add_argument('-d', '--domain', nargs='?', type=str, default='businesscorp.com.br', help='[i] Insira o domain')
    parse.add_argument('-k', '--key', nargs='?', type=str, default='0f4584328935ddafb79eb65ec70bf0c0b0265a88',
                       action='store', help='[i] Sua chave')
    parse.add_argument('-l', '--log', type=str, default='view', help="Caminho do arquivo log")
    parse.add_argument('-t', '--timeout', type=float, default=3, help="[i] timeout")
    parse.add_argument('-p', '--ports',
                       nargs='+',
                       type=int,
                       default=[21, 22, 3389, 6000, 6005, 5900, 9999, 23, 25, 53, 79, 161, 80, 8080, 5000, 8443, 8888,
                                81, 88,
                                110, 111, 113, 135, 139, 143, 443, 445, 500, 1433, 1434, 3306, 5433, 2049],
                       action="store",
                       dest="ports",
                       help='[i] Serviços a reconhecer')
    args = parse.parse_args()
    try:
        if sys.argv[1]:
            # s = Scan('businesscorp.com.br', 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 135, 139, 143, 443, 445)
            s = Scan(args.domain, args.ports, args.timeout, args.key)

            s.ip_api()
            #s.dns_xfr()
            #s.brute_force()
           # multiprocessing.Process(s.top_1()).start()
            #multiprocessing.Process(s.dns_python3()).start()
            #multiprocessing.Process(s.dns_xfr()).start()
            #multiprocessing.Process(s.brute_force()).start()
            s.email_hunter()
    except KeyboardInterrupt:
        sys.exit('\033[41m'"[!]INTERROMPIDO[!] "'\033[0;0m\n''\033[1m')
    except IndexError:
        parse.print_help()
