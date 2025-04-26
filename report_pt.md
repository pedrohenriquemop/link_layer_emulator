# Relatório do Emulador DCCNET

## 1. Introdução

Este documento discute a implementação do emulador DCCNET para dois modos: modo `md5` e modo `xfer` (transferência de arquivos). O emulador foi totalmente implementado em Python utilizando a biblioteca `asyncio`, visando alta interoperabilidade com implementações em outras linguagens conforme exigido. A solução final prioriza robustez na estruturação dos quadros, transmissão e recepção de dados de forma concorrente e aderência estrita às especificações do protocolo DCCNET.

## 2. Desafios e Dificuldades

Os principais desafios enfrentados durante o desenvolvimento foram:

- **Recuperação de Framing**: Detectar corretamente o início e o fim dos quadros baseando-se apenas no padrão SYNC.
- **Envio e Recebimento Concorrentes**: Permitir que dados fluam simultaneamente em ambas as direções sem bloquear o loop de eventos.
- **Tratamento de Timeouts**: Garantir que o transmissor reenvie quadros se ACKs não forem recebidos dentro de um tempo razoável.
- **Cooperatividade com Asyncio**: Prevenir o bloqueio do loop de eventos usando rendição frequente (`await asyncio.sleep(0)`).
- **Interoperabilidade**: Garantir compatibilidade com implementações externas do DCCNET, especialmente na validação de checksum e no formato dos quadros.

De forma inesperada, gerenciar o encerramento da transmissão (EOF) sem fechar a conexão prematuramente exigiu um controle cuidadoso dos sinais `END` e da sincronização de ACKs.

## 3. Mecanismos para Recuperação de Framing Após Erros

O sistema implementa recuperação de framing através de um mecanismo robusto de ressincronização baseado na constante `SYNC` do DCCNET:

1. **Busca de SYNC**: Durante a recepção, o leitor busca continuamente no buffer pelo padrão duplo de SYNC.
2. **Tratamento de Quadros Parciais**: Se um SYNC for encontrado mas o restante do cabeçalho ou payload estiver ausente, o sistema aguarda mais dados.
3. **Verificação de Checksum**: Após identificar um quadro, o checksum é recalculado ignorando o campo de checksum recebido para validar a integridade.
4. **Recuperação de Erros**: Se qualquer etapa falhar (falha de SYNC, erro de checksum, quadro incompleto), o buffer avança um byte e continua procurando um SYNC válido.

Essa abordagem minimiza a perda de dados em casos de erros ou corrupções na rede.

## 4. Transmissão e Recepção Paralelas

A transmissão e a recepção ocorrem de forma concorrente utilizando tarefas separadas do `asyncio`:

- **Tarefa de Envio**: Lê blocos do arquivo de entrada, enquadra-os em quadros DCCNET e os envia. Cada quadro de dados exige um ACK antes de prosseguir.
- **Tarefa de Recebimento**: Escuta continuamente quadros recebidos, verifica sua integridade, envia ACKs e grava os dados válidos no arquivo de saída.
- **Leitor e Demultiplexador**: Uma tarefa de leitor lê bytes crus do socket, reconstrói os quadros e os despacha para filas apropriadas (ACKs ou Dados).

O uso de `await asyncio.sleep(0)` entre transmissões assegura que tanto o envio quanto o recebimento tenham oportunidades iguais de progresso, evitando bloqueio do loop de eventos.

O fluxo de envio utiliza um mecanismo de tentativas (até 16 vezes) se ACKs não forem recebidos, garantindo entrega confiável dos dados. Se um quadro for duplicado, ele é detectado comparando o ID e checksum do último quadro recebido, e ACKs são reenviados sem reprocesar os dados.

## 5. Interface da Aplicação com a Implementação do DCCNET

O emulador oferece uma Interface de Linha de Comando (CLI) com dois modos principais:

- **Modo Servidor (`-s`)**:

  - Escuta em todas as interfaces disponíveis (suporte a IPv6).
  - Aguarda conexões de entrada.
  - Envia o conteúdo de um arquivo de entrada enquanto simultaneamente recebe e salva o arquivo remoto.

- **Modo Cliente (`-c`)**:
  - Conecta-se ativamente a um servidor remoto.
  - Envia o conteúdo de um arquivo de entrada.
  - Simultaneamente recebe e salva o conteúdo enviado pelo servidor.

Exemplo de uso:

```bash
# Iniciar servidor
python dccnet_emulator.py -s 7777 server_input.txt server_output.txt

# Iniciar cliente
python dccnet_emulator.py -c 127.0.0.1:7777 client_input.txt client_output.txt
```

A aplicação gerencia internamente o framing, as tentativas de retransmissão, ACKs, sinais de fim (`END`) e ressincronização, abstraindo toda a complexidade do protocolo DCCNET para o usuário.

## 6. Contribuições de Ferramentas de IA

Ferramentas de IA, como ChatGPT e GitHub Copilot, foram significativamente úteis em:

- Projetar um modelo de concorrência limpo usando `asyncio` para transferência de arquivos bidirecional.
- Escrever trechos repetitivos de código, como serialização (`pack`) e desserialização (`unpack`) de quadros.
- Ajudar a depurar e sugerir melhorias em mecanismos de timeout e retransmissão.
- Explicar problemas sutis de rede como "connection reset by peer" ou bloqueio do loop de eventos com tarefas `asyncio`.

As ferramentas não foram utilizadas diretamente para gerar soluções finais, mas desempenharam papel crítico no brainstorm de ideias, explicação de partes complexas e sugestões de boas práticas, especialmente em programação de rede concorrente.

## 7. Conclusão

O emulador DCCNET cumpre os requisitos da tarefa:

- Interopera com servidores e clientes externos.
- Suporta tratamento robusto de erros e recuperação de framing.
- Gerencia transmissão e recepção bidirecionais e concorrentes.
- Fornece uma interface de linha de comando limpa e amigável.

Embora o projeto envolvesse aspectos complexos de implementação de protocolos de rede, o uso apropriado das primitivas do `asyncio`, a gestão cuidadosa de erros e a estrutura modular do código levaram a uma solução final confiável.
