# Relatório do Script de DHCP e DNS Spoofing

**Nomes:** Patrick Bomm dos Santos, Eduardo Machado

## Objetivo do Script
Este script é projetado para realizar spoofing de DHCP e DNS em uma rede. Ele utiliza a biblioteca [scapy](https://scapy.net/) para enviar e manipular pacotes de rede e [tkinter](https://docs.python.org/3/library/tkinter.html) para fornecer uma interface gráfica ao usuário.

## Descrição do Funcionamento
O script possui as seguintes funcionalidades principais:

1. **Configuração Padrão do Servidor DHCP Falso:**

   - IP do servidor DHCP: `192.168.1.1`
   - MAC do servidor DHCP: `02:42:ac:11:00:02`
   - Máscara de sub-rede: `255.255.255.0`
   - Tempo de concessão: `86400` segundos
   - Servidor DNS: `127.0.0.1`
   - Gateway padrão: `192.168.1.1`
   - IP atribuído: `192.168.1.100`
   - Tabela de spoofing DNS para domínios específicos.

2. **Listagem das Interfaces de Rede:**

   - Usa a biblioteca [psutil](https://pypi.org/project/psutil/) para listar todas as interfaces de rede disponíveis no sistema.

3. **Sniffing de Pacotes DHCP e DNS:**

   - Captura pacotes DHCP e DNS na rede com base em filtros especificados (IP e/ou MAC alvo).
   - Usa a função [sniff](https://scapy.readthedocs.io/en/latest/usage.html#sniffing) da biblioteca [scapy](https://scapy.net/) para realizar a captura dos pacotes.

4. **Manipulação de Pacotes:**

   - Função `handle_packet` para identificar e manipular pacotes DHCP e DNS.
   - Funções `send_dhcp_offer` e `send_dhcp_ack` para enviar pacotes DHCP OFFER e ACK respectivamente.
   - Função `dns_spoof` para responder consultas DNS com IPs falsos.

5. **Interface Gráfica:**

   - Utiliza [tkinter](https://docs.python.org/3/library/tkinter.html) para criar uma interface gráfica que permite ao usuário selecionar a interface de rede, inserir IP e MAC alvo, e visualizar logs de pacotes capturados e ações realizadas.

## Funcionalidades e Componentes do Script

### Configuração Padrão do Servidor DHCP Falso
- **Variáveis Padrão:** Define valores padrão para IP, MAC, máscara de sub-rede, tempo de concessão, servidor DNS, gateway padrão, IP atribuído e tabelas de spoofing DNS.

### Listagem das Interfaces de Rede
- **Função `list_working_interfaces`:** Utiliza a biblioteca [psutil](https://pypi.org/project/psutil/) para listar todas as interfaces de rede disponíveis.

### Sniffing de Pacotes DHCP e DNS
- **Função `start_sniffing`:** Inicia a captura de pacotes com base nos filtros especificados para IP e/ou MAC alvo.
- **Função `handle_packet`:** Identifica e manipula pacotes DHCP e DNS, chamando funções específicas para cada tipo de pacote.
- **Função `send_dhcp_offer`:** Cria e envia pacotes DHCP OFFER.
- **Função `send_dhcp_ack`:** Cria e envia pacotes DHCP ACK.

### Manipulação de Pacotes DNS
- **Função `dns_spoof`:** Responde a consultas DNS com IPs falsos definidos na configuração.

### Interface Gráfica
- **Uso do [tkinter](https://docs.python.org/3/library/tkinter.html):** Cria uma interface gráfica que permite ao usuário selecionar a interface de rede, inserir IP e MAC alvo, e visualizar logs de pacotes capturados e ações realizadas.

### Iniciando a Captura de Pacotes
- **Função `start_sniffing_thread`:** Inicia a captura de pacotes em uma nova thread.
- **Função `update_config`:** Atualiza a configuração global com base nos valores inseridos pelo usuário na interface gráfica.

## Conclusão
O script fornece uma maneira completa de realizar spoofing de DHCP e DNS em uma rede local. Ele permite ao usuário selecionar interfaces de rede, especificar alvos por IP e/ou MAC, e visualizar logs detalhados das atividades de spoofing em tempo real através de uma interface gráfica amigável.



# Tutorial para Executar o Script de DHCP e DNS Spoofing

## Requisitos
Antes de executar o script, certifique-se de que você possui os seguintes requisitos instalados:

1. **Python 3.x:** Você pode baixar e instalar o Python a partir do [site oficial](https://www.python.org/downloads/).
2. **Bibliotecas Python necessárias:** Instale as bibliotecas `psutil`, `scapy` e `tkinter`. Você pode instalá-las usando o pip:

```sh
pip install psutil scapy
```

3. **Wireshark:** Certifique-se de que o Wireshark está instalado em seu sistema para capturar e analisar pacotes de rede.

## Passo a Passo

### 1. Baixe o Script
Baixe o script Python fornecido e salve-o em um diretório em seu computador.

### 2. Execute o Script
Abra um terminal ou prompt de comando e navegue até o diretório onde o script foi salvo. Execute o comando abaixo para iniciar o script:

```sh
python dhcp_spoofing.py
```

### 3. Interface Gráfica
Quando o script for executado, uma janela da interface gráfica será exibida. Esta interface possui duas abas: "Main" e "Configuration".

#### Aba "Main"
1. **Selecionar Interface de Rede:**
   - Use o menu suspenso para selecionar a interface de rede que deseja usar para o spoofing.

2. **Inserir IP Alvo (Opcional):**
   - Insira o IP alvo no campo "Target IP". Deixe em branco para capturar todos os IPs.

3. **Inserir MAC Alvo (Opcional):**
   - Insira o MAC alvo no campo "Target MAC". Deixe em branco para capturar todos os MACs.

4. **Iniciar Spoofing:**
   - Clique no botão "Start Spoofing" para iniciar a captura e spoofing de pacotes.

#### Aba "Configuration"
1. **Configurar Servidor DHCP Falso:**
   - Edite os campos conforme necessário para configurar o servidor DHCP falso.
   - Campos disponíveis: `DHCP Server IP`, `DHCP Server MAC`, `Subnet Mask`, `Lease Time`, `DNS Server`, `Default Gateway`, `Assigned IP`.

2. **Atualizar Configurações:**
   - Clique no botão "Update Configuration" para aplicar as novas configurações.

### 4. Monitorar Log
Na aba "Main", você verá um campo de texto onde os logs das atividades de spoofing serão exibidos. Isso inclui pacotes capturados, pacotes enviados e outras informações relevantes.

### 5. Parar o Script
Para parar o script, você pode simplesmente fechar a janela da interface gráfica. Isso interromperá todas as atividades de sniffing e spoofing.

### Nota
- Este script é apenas para fins educacionais e de teste em ambientes controlados. O uso de ferramentas de spoofing em redes de produção ou sem a devida autorização é ilegal e antiético.

Seguindo estes passos, você deverá ser capaz de executar e utilizar o script de DHCP e DNS spoofing com sucesso.