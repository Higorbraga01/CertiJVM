# CertiJVM

Aplicativo gráfico em português para adicionar, atualizar, remover e conferir certificados no `cacerts` de múltiplas JDKs/JREs Java 8+ no Windows e Ubuntu 22.04+.

## Executar a partir do código

É necessário Python 3.10+, um JDK com `javac` para compilar o módulo de teste Java e acesso às dependências Python.

No Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe build.py
```

No Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y libegl1
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python build.py
```

Para desenvolvimento, compile `src/jvmcert/java/TlsProbe.java` com `javac --release 8 -d src/jvmcert/java src/jvmcert/java/TlsProbe.java` e execute `python launcher.py`. O pacote portátil fica em `dist/CertiJVM/`, e um ZIP para distribuição em `dist/CertiJVM-Windows.zip` ou `dist/CertiJVM-Linux.zip`. O GitHub Actions gera artefatos separados para Windows e Ubuntu; o pacote precisa ser construído no respectivo sistema operacional.

No Ubuntu, a interface Qt também precisa da biblioteca de sistema `libegl1` ao executar o pacote portátil.

## Uso

1. Em **JVMs**, clique em **Buscar JVMs** para autorizar a descoberta nesta abertura. Selecione uma ou várias instalações encontradas, ou escolha a pasta de uma instalação manualmente. O aplicativo não faz essa busca ao iniciar.
2. Em **Certificados**, escolha arquivos `.crt`, `.cer` ou `.pem`. Você também pode informar uma URL HTTPS: para endpoints comuns o aplicativo lê a cadeia TLS e pré-seleciona o certificado do servidor; para links terminados em `.crt`, `.cer` ou `.pem` ele baixa o arquivo. Confira assunto, validade e SHA-256 antes de continuar.
3. Edite o alias, se necessário. Para arquivos locais, informe uma **URL de teste** quando quiser validar a conexão HTTPS pela JVM após importar.
4. Em **Revisão**, informe a senha do `cacerts` (normalmente `changeit`), escolha adicionar/atualizar ou remover, confira cada JVM e confirme.
5. Em **Resultados**, veja a operação, a impressão digital conferida e o resultado do teste Java. Um HTTP 401/404 com TLS válido é considerado conexão TLS bem-sucedida.

URLs, caminhos de arquivos, aliases editados e URLs de teste são salvos nas configurações do usuário; a senha não é salva. Configurações da versão anterior são lidas automaticamente e salvas no novo diretório `certijvm` na próxima alteração. Os aliases de certificados já instalados continuam válidos. Para remover um alias sem arquivo correspondente, use o campo **Alias avulso para remover** na revisão. Ao atualizar, uma cópia temporária do `cacerts` é criada e restaurada se a operação falhar. Se a restauração também falhar, o aplicativo informa o caminho da cópia para recuperação manual. Certificados fora do período de validade não podem ser importados. Reinicie aplicações Java já em execução para que carreguem o truststore atualizado.

Para instalações protegidas, o aplicativo solicita UAC no Windows ou usa `pkexec` no Ubuntu ao gravar. No Ubuntu, `pkexec` e um agente de autenticação gráfica devem estar instalados. O aplicativo altera somente o `cacerts` padrão de cada JVM escolhida; aplicações com truststore personalizado não são cobertas.

As operações mostram seu andamento na parte superior da janela. Buscas por JVMs e URLs podem ser canceladas; uma conexão ou verificação Java já iniciada pode demorar até o timeout para terminar. No Windows, os processos auxiliares são executados sem abrir terminais. O diálogo de autorização UAC continua visível quando necessário.
