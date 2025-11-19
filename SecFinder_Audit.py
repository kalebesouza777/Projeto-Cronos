# -*- coding: utf-8 -*-
#
# PROJETO CRONOS - FERRAMENTA DE AUDITORIA DEFENSIVA
#
# Objetivo: Pipeline automatizado para caça e detecção de segredos (chaves de API, tokens)
# expostos em arquivos JavaScript de ambientes de desenvolvimento, staging ou repositórios
# de código-fonte abertos (Open Source).
#
# Uso: Projetos White-Hat para auditoria de segurança própria.
#
import requests
import re
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import os

# --- 1. DEFINIÇÕES DE SEGREDOS (REGEX) ---
# O coração do script: Padrões de detecção (Regex)
SECRET_PATTERNS = {
    "AWS_KEY": r'(A3T.{10}|AKIA[0-9A-Z]{16})', # AWS Access Key ID
    "FIREBASE_API_KEY": r'AIza[0-9A-Za-z-_]{35}', # Google Firebase API Key
    "STRIPE_KEY": r'(sk_live_[0-9a-zA-Z]{24})', # Stripe Live Secret Key
    "GITHUB_TOKEN": r'(ghp_[0-9a-zA-Z]{36})', # GitHub Personal Access Token (PAT)
    "SLACK_TOKEN": r'(xoxb-[0-9]{10,15}-[0-9]{10,15}-[0-9a-zA-Z]{24})', # Slack Bot Token
    "GENERIC_SECRET": r'(\w*secret[\w_]*|password[\w_]*|api_key[\w_]*)\s*[:=]\s*["\']([^"\']{15,})["\']', # Segredos genéricos (crítico!)
    "GOOGLE_API_KEY": r'AIza[0-9A-Za-z\-_]{35}', # Google API Key padrão
    "TWILIO_SID": r'AC[a-f0-9]{32}', # Twilio Account SID
    "ROBLOX_API_KEY": r'(RBX-[0-9a-zA-Z]{32,})',
}

def find_secrets(content, source_url):
    """Procura por todos os padrões de segredo no conteúdo do arquivo JS."""
    found_secrets = []
    
    for name, pattern in SECRET_PATTERNS.items():
        # Captura tanto o padrão completo quanto o grupo de captura (se houver)
        matches = re.findall(pattern, content, re.IGNORECASE)
        
        for match in matches:
            # Verifica se o resultado é uma tupla (caso tenha grupos de captura) ou apenas a string
            key_value = match[1] if isinstance(match, tuple) and len(match) > 1 else match
            
            # Garante que a chave é uma string e tem um tamanho mínimo para ser relevante
            if isinstance(key_value, str) and len(key_value) > 15:
                # Mascara a chave para o log (proteção de log e ética)
                masked_key = f"{key_value[:5]}***{key_value[-5:]}"
                
                # Armazena apenas a versão mascarada, para fins de auditoria
                found_secrets.append({
                    "type": name,
                    "key_masked": masked_key,
                    "source_url": source_url,
                })
                
    return found_secrets

def get_js_links(base_url, content):
    """Extrai todas as referências de arquivos JS do HTML, filtrando apenas o mesmo domínio."""
    soup = BeautifulSoup(content, 'html.parser')
    js_urls = set()
    
    for script in soup.find_all('script', src=True):
        src = script.get('src')
        full_url = urljoin(base_url, src)
        # Filtra para manter o foco no domínio alvo
        if full_url.endswith('.js') and urlparse(full_url).netloc == urlparse(base_url).netloc:
            js_urls.add(full_url)
            
    return list(js_urls)

def run_js_key_hunter(target_url):
    """Executa o fluxo completo do scanner White-Hat."""
    print(f"[*] PROJETO CRONOS - AUDITORIA: Iniciando scanner em: {target_url}")
    
    # 1. Definir Headers (sem Cookie, usando apenas User-Agent padrão)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Auditor/1.0; Project Cronos)', # User-Agent de auditoria
    }
    
    # 2. Obter HTML da página alvo
    try:
        response = requests.get(target_url, headers=headers, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao acessar o alvo {target_url}: {e}")
        print("[DICA] O alvo deve ser acessível publicamente (Status 200).")
        return
        
    # 3. Extrair links JS
    js_files = get_js_links(target_url, response.text)
    
    if len(js_files) == 0: 
        print(f"[AVISO] Não foram encontrados arquivos JS referenciados no HTML. Analisando apenas o código-fonte da página principal.")

    print(f"[*] Encontrados {len(js_files)} arquivos JS para análise.")

    all_secrets = []

    # Analisa o HTML principal (segredos embutidos)
    secrets_in_html = find_secrets(response.text, target_url + " (HTML Principal)")
    if secrets_in_html:
        all_secrets.extend(secrets_in_html)
        print(f"[ACHADO!] {len(secrets_in_html)} Segredo(s) encontrado(s) no HTML principal!")

    # 4. Baixar e analisar cada arquivo JS
    for js_url in js_files:
        print(f"[*] Analisando: {js_url}")
        try:
            # Baixa o conteúdo do JS
            js_content = requests.get(js_url, headers=headers, timeout=15).text
            
            secrets = find_secrets(js_content, js_url)
            
            if secrets:
                all_secrets.extend(secrets)
                print(f"  [SUCESSO] {len(secrets)} segredo(s) encontrado(s) em {js_url}!")
            
        except requests.exceptions.RequestException as e:
            print(f"  [ERRO] Falha ao baixar {js_url}: {e}")
            continue

    # 5. Relatório final
    print("\n" + "—"*50)
    print(f"| RELATÓRIO FINAL DO PROJETO CRONOS |")
    print(f"| Ferramenta de Auditoria White-Hat |")
    print("—"*50)
    
    if all_secrets:
        print(f"| {len(all_secrets)} Ocorrência(s) de Segredo(s) Encontrada(s) no alvo: {target_url}")
        print("—"*50)
        for i, secret in enumerate(all_secrets, 1):
            print(f"[{i:02d}] TIPO: {secret['type']}")
            print(f"      LOCAL: {secret['source_url']}")
            print(f"      CHAVE (Mascarada): {secret['key_masked']}")
            print("-" * 20)
    else:
        print("| NENHUM segredo crítico encontrado. O alvo está limpo. |")

    print("—"*50 + "\n")

if __name__ == "__main__":
    # Verifica se a URL foi passada como argumento de linha de comando
    if len(sys.argv) < 2:
        print("Uso: python3 SecFinder_Audit.py <URL_DO_ALVO>")
        print("Exemplo: python3 SecFinder_Audit.py http://localhost:8000")
        sys.exit(1)
        
    TARGET_URL = sys.argv[1]
    run_js_key_hunter(TARGET_URL)