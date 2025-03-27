import whois
import pandas as pd
from tldextract import extract
from Levenshtein import distance as levenshtein_distance

# Ler a lista de domínios legítimos de um arquivo TXT
with open('dominios_legitimos_cliente', 'r') as file:
    legit_domains = [line.strip() for line in file.readlines()]
print(f"Domínios legítimos: {legit_domains}")  # Adicionado para depuração

# Ler a lista de domínios suspeitos de um arquivo Excel
df_suspicious = pd.read_excel('dominios_suspeitos.xlsx')
suspicious_domains = df_suspicious['content'].tolist()
print(f"Domínios suspeitos: {suspicious_domains}")  # Adicionado para depuração

# Função para verificar se um domínio é semelhante a qualquer domínio legítimo (para spear phishing e typosquatting)
def is_domain_similar(domain, legit_domains):
    # Extrair o subdomínio, domínio e sufixo do domínio suspeito
    extracted = extract(domain)
    domain_to_check = f"{extracted.domain}.{extracted.suffix}"
    
    # Verificar se o domínio extraído é semelhante a qualquer domínio legítimo
    for legit in legit_domains:
        legit_extracted = extract(legit)
        legit_domain = f"{legit_extracted.domain}.{legit_extracted.suffix}"
        
        # Se os domínios forem idênticos, retornar False
        if domain_to_check == legit_domain:
            return False
        
        # Calcular a distância de Levenshtein entre os domínios
        if levenshtein_distance(domain_to_check, legit_domain) <= 4:  # Ajuste o valor conforme necessário
            return True
    
    return False

# Criar uma lista para armazenar os resultados
results = []

# Função para realizar a consulta WHOIS
def perform_whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return str(e)

# Percorrer os domínios suspeitos
for domain in suspicious_domains:
    print(f"Verificando domínio: {domain}")  # Adicionado para depuração
    # Verificar se o domínio é semelhante a um domínio legítimo e não é idêntico
    if is_domain_similar(domain, legit_domains):
        print(f"Domínio {domain} é semelhante a um domínio legítimo.")  # Adicionado para depuração
        whois_info = perform_whois_lookup(domain)
        results.append({
            "Domínio": domain,
            "WHOIS": whois_info
        })

# Converter a lista de resultados em um DataFrame
df_results = pd.DataFrame(results)

# Salvar o DataFrame em um arquivo Excel (XLSX)
df_results.to_excel('whois_suspicious_domains.xlsx', index=False)

print("Informações WHOIS dos domínios suspeitos semelhantes foram salvas em 'whois_suspicious_domains.xlsx'.")

