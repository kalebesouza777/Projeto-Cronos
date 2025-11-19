

⚡ Projeto Cronos: Scanner de Segredos em JavaScript (White-Hat Audit)

Visão Geral

O Projeto Cronos é um pipeline automatizado em Python projetado para fortalecer a segurança de aplicações web, identificando a exposição acidental de credenciais críticas (chaves de API, tokens de acesso, segredos de serviço) em arquivos JavaScript.

O projeto foi desenvolvido com foco em Automação de Auditoria Defensiva, visando ambientes de desenvolvimento, staging e repositórios de código aberto (Open Source).

Tecnologias Envolvidas: Python, requests, BeautifulSoup4, Expressões Regulares (Regex).

💡 Por que o Projeto Cronos?

O vazamento de segredos em JavaScript é uma falha de segurança comum que permite a invasores assumir contas, acessar bancos de dados ou consumir serviços de terceiros (como AWS, Twilio, Stripe). Este script simula o comportamento de um auditor de segurança (White-Hat) para detectar tais exposições antes que sejam exploradas.

✨ Principais Funcionalidades

Rastreamento Automático: Analisa uma URL-alvo, extraindo todos os links de arquivos .js referenciados.

Análise de Conteúdo: Baixa o conteúdo de cada arquivo JS e do HTML principal.

Detecção de Segredos: Aplica um dicionário robusto de Expressões Regulares (Regex) para identificar padrões de credenciais conhecidas (AWS Keys, Firebase API Keys, Stripe Live Keys, etc.).

Relatório Limpo: Gera um relatório formatado, mascarando os segredos encontrados para evitar exposição e cumprir diretrizes éticas.

⚙️ Como Usar

Pré-requisitos

Python 3.x

Bibliotecas: requests e beautifulsoup4

# 1. Ative seu ambiente virtual (Kali Linux)
source osint_env/bin/activate

# 2. Instale as dependências
pip install requests beautifulsoup4


Execução

O script agora requer que você passe a URL do alvo diretamente como argumento.

# Sintaxe: python3 SecFinder_Audit.py <URL_DO_ALVO>

# Exemplo: Executando contra um ambiente de teste local
python3 SecFinder_Audit.py http://localhost:8000

# Exemplo: Executando contra um site público (para fins de auditoria e teste de regex)
python3 SecFinder_Audit.py [https://www.google.com](https://www.google.com)


Resultado

O script exibirá um relatório detalhado com o tipo de segredo encontrado, a URL do arquivo JS ou HTML onde foi localizado e uma versão mascarada da chave para fins de auditoria.

Desenvolvido por: Kalebe Souza 
hackerone: Shark7_7
Foco: Automação e Segurança
