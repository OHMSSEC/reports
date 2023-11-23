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
