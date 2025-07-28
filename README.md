# Meu App Financeiro

Sistema de gestão de contratos financeiros desenvolvido em Flask.

## Funcionalidades Principais

- Cadastro, edição e exclusão de contratos financeiros
- Filtros avançados por instituição, modalidade, status, ano, mês, etc.
- Relatórios dinâmicos com gráficos e tabelas
- Detalhamento completo dos contratos (modalidade, sistema de amortização, valores pagos/pendentes, datas, etc.)
- Cálculo automático de saldo devedor, valor da parcela, datas e totais
- Visual moderno, responsivo e com as cores da empresa
- Autocomplete de instituição
- Cards de resumo, badges de status, botões e tabelas padronizados
- Importação de contratos via arquivo ou API
- Logs de ações do sistema
- Painel de taxas e histórico de taxas
- **Assistente IA local** para dúvidas rápidas sobre contratos e uso do sistema

## Assistente IA Local

O sistema possui um assistente inteligente que responde perguntas simples sobre os contratos cadastrados, sem depender de API externa.

### Como funciona?
Clique em "Assistente IA" no menu. Você verá um botão para exibir dicas de uso. O assistente entende perguntas como:

- "Como estão os contratos?"
- "Quantos contratos ativos?"
- "Quais contratos estão quitados?"
- "Informações dos contratos"
- "Resumo dos contratos"
- "Qual o saldo devedor total?"
- "Quais empresas têm contratos?"
- "Quais instituições?"
- "Me mostre os contratos da empresa X"
- "Me mostre os contratos da instituição Y"
- "Detalhes do contrato X"
- Perguntas genéricas ("ajuda", "olá", etc.)

> Dica: Seja objetivo e use palavras-chave dos contratos, empresas ou instituições cadastradas.

## Instalação

1. Clone o repositório:
   ```bash
   git clone <url-do-repositorio>
   cd meu_app_financeiro-2
   ```
2. Crie e ative um ambiente virtual (opcional, mas recomendado):
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```
3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Execute o sistema:
   ```bash
   python app.py
   ```
5. Acesse no navegador: [http://localhost:5000](http://localhost:5000)

Usuário padrão: **admin**  
Senha padrão: **admin123**

## Estrutura do Projeto

- `app.py` — Backend Flask
- `templates/` — Templates HTML (Jinja2)
- `static/` — CSS, JS e imagens
- `instance/contratos.db` — Banco de dados SQLite
- `requirements.txt` — Dependências Python

## Observações
- O assistente IA funciona localmente, sem custos ou necessidade de API externa.
- Para dúvidas ou sugestões, entre em contato com o desenvolvedor.

---

© 2025 — Meu App Financeiro
