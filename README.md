# TecHackPortScanner

## Descrição

Esse repositório contém um scanner de portas desenvolvido em Python. O scanner é capaz de verificar se uma porta está aberta ou fechada ou filtrada em um determinado host ou network. O programa também é capaz de identificar possíveis sistemas operacionais com base nos banners capturados e permite várias opções de uso, como, utilização de IPv4 ou IPv6 e utilização de protocolo TCP ou UDP para o scan.

## Recursos Principais

- Escaneia intervalos de portas TCP ou UDP
- Suporte para escaneamento de hosts individuais, redes inteiras e websites (IPs já resolvidos em domínios)
- Identifica portas abertas, fechadas e filtradas
- Agrupa e exibe resultados de forma organizada
- Identifica possíveis sistemas operacionais com base nos banners capturados

## Funcionamento

O programa solicita ao usuário que escolha entre três modos de escaneamento:

1. **Single (Host único)**: Escaneia um host específico fornecido pelo usuário.
2. **Network (Rede inteira)**: Analisa todos os endereços IP de uma sub-rede.
3. **Website**: Resolve um domínio para um endereço IP e escaneia suas portas.

### Gerando Partes do Escaneamento

A função `generate_chunks` divide o intervalo de portas em partes menores para otimizar a distribuição entre threads.

### Executando o Escaneamento

A função `scan` tenta conectar-se a cada porta do IP fornecido:

- Para TCP: Usa `connect_ex` para verificar se a porta está aberta ou fechada.
- Para UDP: Envia um pacote e verifica a resposta para determinar o status.

### Armazenamento e Organização dos Resultados

Os resultados são armazenados e posteriormente exibidos de forma organizada, agrupando as portas abertas, fechadas e filtradas no terminal.

### Escaneamento de Rede

A função `network_scan` percorre todos os endereços IP de uma rede e executa o escaneamento para cada um.

### Identificação de Sistemas Operacionais

A função `banner_grab` tenta obter banners de serviços rodando nas portas abertas e os compara com palavras-chave para identificar o sistema operacional do host. É possível que o programa não consiga encotrar um banner para identificar o sistema operacional.

## Como Utilizar

1. Execute o script Python.
2. Escolha entre os modos "single", "network" ou "website".
3. Informe o IP, rede ou domínio a ser analisado.
4. Defina o intervalo de portas e o protocolo (TCP ou UDP).
5. Aguarde a conclusão do escaneamento e visualize os resultados.

## Observações

- O escaneamento de redes pode ser considerado invasivo; É possível que a leitura de portas só seja permitida se o Firewall do host for desativado.

## Referências e onde elas foram utilizadas

- [Write a port scanner in Python in 5 minutes | Free Cyber Work Applied series](https://youtu.be/t9EX2RAUoTU?si=GSbqcF6xrOesOZbg) -> Utilizado para entender o funcionamento de um scanner de portas e implementar o scan de um ip unitário.

- [Create a Multithreaded Port Scanner with Python](https://youtu.be/nYPV1rCVdvs?si=ib2BoitEB5KZy65j) -> Utilizado para entender como implementar um scanner de portas multithread.

- [Criando um Banner Grabber em PYTHON!](https://youtu.be/mxBwRETDqIY?si=u3gfyiOeuD-0ZzRY) -> Utilizado para entender e como referência para implementar um banner grabber.

- [How to verify that a UDP port is open](https://networkengineering.stackexchange.com/questions/26541/how-to-verify-that-a-udp-port-is-open) -> Utilizado para entender que se a resposta foi recebida, a porta está aberta; Se um mensagem ICMP 'Port Unreachable' foi retornada, a porta está fechada.
