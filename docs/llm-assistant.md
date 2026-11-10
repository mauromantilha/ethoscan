# Assistente LLM (aikido)

Analista consultivo embutido no Ethoscan: **tria findings** (real / falso positivo /
inconclusivo / informativo), **correlaciona achados** em cadeias plausíveis, sugere
**próximos passos manuais** e responde perguntas sobre um job via chat.

**Advisory-only por design**: o modelo analisa e sugere, nunca executa scans. O
system prompt é fixo (não controlável pelo usuário da UI) e proíbe sugerir ações
fora do RoE.

## O que é enviado ao provedor

Data minimization — apenas:

- metadados do engagement/job (nome, escopo, intensidade, estado, tools, resumo
  de `tool_runs`);
- findings truncados: título, severidade, tool, alvo, CVE/CWE, descrição (400
  chars), evidência (300 chars), máximo de **60 findings** por requisição.

Artefactos brutos (pcaps, outputs completos), segredos e credenciais **nunca**
saem do host. Cada uso é auditado (`llm_analyze` / `llm_assistant`).

## Configuração

O assistente aceita **qualquer endpoint OpenAI-compatível** — trocar de
provedor/modelo é editar 3 linhas no `.env` e reiniciar a API:

```env
ETHOSCAN_LLM_BASE_URL=<endpoint>
ETHOSCAN_LLM_API_KEY=<key>          # vazio para Ollama/LM Studio local
ETHOSCAN_LLM_MODEL=<modelo>
```

Sem `BASE_URL` + `MODEL` preenchidos, os endpoints respondem **503**,
`/health` mostra `llm_enabled: false` e nada é enviado a terceiros.

### Provedores

| Provedor | BASE_URL | Modelos | Custo |
|---|---|---|---|
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini`, `gpt-4o` | pago, barato |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile`, `llama-3.1-8b-instant` | **free tier** |
| **OpenRouter** | `https://openrouter.ai/api/v1` | modelos com sufixo `:free` (ex.: `meta-llama/llama-3.3-70b-instruct:free`) | **gratuitos** |
| **Cloudflare Workers AI** | `https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1` | `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | free allocation |
| **Ollama (local)** | `http://host.docker.internal:11434/v1` | `llama3.1:8b` etc. (`ollama pull ...`) | grátis, offline |

> **Sensibilidade**: findings de pentest descrevem portas, versões e
> vulnerabilidades dos seus alvos. Para engajamentos com NDA/escopo restritivo,
> prefira **Ollama local**; para labs próprios, qualquer provedor serve.

Aplicar:

```bash
sudo docker compose up -d --build api worker   # ou restart da API local
curl -s http://127.0.0.1:8000/health | python3 -m json.tool | grep llm
```

## Uso

### API

```bash
# ping ao provedor (valida BASE_URL/KEY/MODEL, mede latência)
curl -X POST -H "X-API-Key: $TOKEN" http://127.0.0.1:8000/api/llm/test

# triagem + correlação + próximos passos
curl -X POST -H "X-API-Key: $TOKEN" http://127.0.0.1:8000/api/jobs/3/analyze

# chat sobre o job
curl -X POST -H "X-API-Key: $TOKEN" http://127.0.0.1:8000/api/jobs/3/assistant \
  -H 'Content-Type: application/json' \
  -d '{"question": "por que o nmap falhou?", "history": []}'
```

### Desktop

Aba **Assistente**: escolha o job → **Analisar achados** (triagem renderizada) ou
converse no chat. Modelos com raciocínio fraco podem gerar triagens vagas —
modelos ≥ 8B são recomendados. O botão **Testar API** faz um ping ao provedor
(`POST /api/llm/test`) e mostra modelo, latência e resposta — falhas de
autenticação/rede aparecem com o detalhe devolvido pelo provedor.

## Limitações

- O modelo só vê o contexto truncado; evidência completa fica nos artefactos.
- Triagem é **hipótese**, não prova: valide antes de reportar ao cliente.
- Responses em JSON estrito dependem do suporte do provedor a
  `response_format`; provedores sem suporte recebem a instrução equivalente e o
  parser tolera cercas de código.
- `history` limitado a 20 mensagens com papéis `user`/`assistant` validados.
