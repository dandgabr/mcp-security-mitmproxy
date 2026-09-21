# Plano de Teste Integrado E2E e Conformidade das 18 Ferramentas — Fase 5

> **Documento de Arquitetura de Software · Fase 5**
> Companion de [0001-arquitetura-e-contratos-mcp.md](./0001-arquitetura-e-contratos-mcp.md) e [0003-fase-4-regras-addons.md](./0003-fase-4-regras-addons.md).
> Papel: Arquiteto de Software. Executores: Dev Backend (implementação), Dev QA (execução, carga e cobertura), Sec · Desenvolvimento Seguro (R1–R5).

---

## 0. Estado medido no início da Fase 5

Verificado nesta sessão com comandos reais, não inferido:

| Item | Medição | Comando |
| :--- | :--- | :--- |
| Tools registradas | **18** (12 Fase 3 + 6 Fase 4) | `create_server().list_tools()` |
| Contratos com `params` tipado | 18/18 | idem |
| Tools parametrizadas | 17/18 (`session_list` sem parâmetros) | idem |
| Outputs com envelope `ToolResult` | 18/18 (campo `ok`) | `output_schema` |
| Suíte existente | **221 passed** | `pytest -q` |
| Resources registrados | **0** | `list_resources()` |
| Prompts registrados | **0** | `list_prompts()` |

---

## 1. Verificação de Conformidade das 18 Ferramentas

**Gate estático criado:** [`tests/test_tool_conformance.py`](../../tests/test_tool_conformance.py) — 28 testes, verdes. Ele falha se uma tool desaparecer, ganhar um input não-tipado, perder o `additionalProperties: false` ou deixar de publicar `output_schema`, e reafirma que as 8 opções de mutação seguem reservadas.

### 1.1 Matriz de conformidade (por família)

| Família | Tools | Fase | Conformidade verificada |
| :--- | :--- | :--- | :--- |
| mitmdump | `mitmdump_start`, `mitmdump_stop`, `mitmdump_replay` | 3 | schema tipado, output `ToolResult`, paths via `ensure_allowed` |
| mitmweb | `mitmweb_start`, `mitmweb_stop`, `mitmweb_get_flows`, `mitmweb_get_flow_detail` | 3 | R1 bind default loopback, R4 redação default |
| core | `mitm_execute_command`, `mitm_export_flow`, `mitm_filter_flows` | 3 | allowlist de comandos, export redigido |
| sessão | `session_list`, `session_status` | 2/3 | leitura pura |
| regras | `mitm_set_map_remote`, `mitm_set_map_local`, `mitm_modify_headers`, `mitm_modify_body`, `mitm_list_rules`, `mitm_clear_rules` | 4 | `ensure_allowed` no `map_local`; `@` bloqueado; read-modify-write |

### 1.2 Achado de conformidade (para decisão do Backend)

**A-1 — Input aninhado em `params`.** Todas as 17 tools parametrizadas expõem o schema como `{"params": {…}}` em vez dos campos achatados na raiz. Consequência: um cliente MCP chama `mitmdump_start` com `{"params": {"mode": [...]}}`, não `{"mode": [...]}`. É o artefato de anotar o handler como `params: XInput` (`Context` é excluído, restando um único campo). Não viola nenhum invariante (o schema é válido e tipado), mas é uma decisão de ergonomia de contrato que deve ser **consciente e documentada**. Duas saídas: (a) aceitar e registrar em ADR o formato `params`; (b) achatar, passando os campos do modelo como argumentos, ao custo de perder o objeto validado de uma vez. Recomendação do Arquiteto: **(a)**, por estabilidade de schema e menor risco; a decisão vai para o ADR-0004.

---

## 2. Cenários E2E (ponta a ponta)

Cada cenário sobe instâncias reais de `mitmdump`/`mitmweb`, usa um servidor alvo local e verifica o efeito observável no cliente. Todos são marcados com `pytest.mark.integration` e fazem *skip* limpo quando o binário não existe.

### 2.1 E2E-A — Captura e leitura (httpbin local)

```
Cliente httpx ──proxy──▶ mitmweb ──▶ Servidor alvo local (aiohttp/http.server)
                             │
                             └── REST: mitmweb_get_flows → mitmweb_get_flow_detail
```

* **Dado** um `mitmweb_start` em modo `regular` com `save_path` em `allowed_dump_roots`,
* **Quando** o cliente envia `GET /api/v1/user` e `POST /login` pelo proxy,
* **Então** `mitmweb_get_flows` retorna ≥2 flows com método/host/status corretos; `mitmweb_get_flow_detail` do `POST /login` mostra os headers do request; e um header `Authorization` aparece **redigido** (R4).

### 2.2 E2E-B — Mock com `map_local` (defesa LFI ativa)

* **Dado** um arquivo `mock_user.json` sob `allowed_mock_roots` e uma sessão ativa,
* **Quando** o agente chama `mitm_set_map_local` para `/api/v1/user` e o cliente requisita essa rota,
* **Então** a resposta é o conteúdo do arquivo com `200`, e
* **E** `mitm_set_map_local` com `/etc/passwd` retorna `ok=false`, `code=PATH_NOT_ALLOWED`, **e nenhuma opção é escrita no proxy** (verificar `GET /options` inalterado).
* **E** o mesmo com um symlink dentro da raiz apontando para `/etc/passwd` é recusado (a canonicalização resolve o link).

### 2.3 E2E-C — Rewrite de rota e injeção de header

* **Dado** um segundo servidor alvo (staging) em outra porta,
* **Quando** `mitm_set_map_remote` redireciona `/old/` → `http://127.0.0.1:<staging>/new/` e `mitm_modify_headers` injeta `X-Audit: 1` nas respostas (`~s`),
* **Então** o cliente vê o corpo do staging e o header `X-Audit` na resposta;
* **E** `mitm_list_rules` reporta as duas regras com `valid=true`; `mitm_clear_rules` zera os contadores.

### 2.4 E2E-D — Replay de servidor a partir de dump

* **Dado** um `.mitm` gravado na E2E-A,
* **Quando** `mitmdump_replay` com `server_replay=[dump]`,
* **Então** uma requisição à URL original retorna a resposta gravada sem tocar a rede externa (`replay_kill_extra`).

### 2.5 E2E-E — Exportação e filtro offline

* **Dado** o dump da E2E-A,
* **Quando** `mitm_export_flow(format="curl")` e `mitm_filter_flows("~m POST & ~u /login")`,
* **Então** o conteúdo é um `curl -X POST …` reproduzível e o filtro retorna exatamente o flow correspondente; o conteúdo exportado está redigido (R4).

### 2.6 E2E-F — Sessão inválida e erros de contrato

* `mitmweb_get_flows` com `session_id` inexistente → `SESSION_NOT_FOUND` (nunca exceção).
* `mitm_execute_command` com comando fora da allowlist → `COMMAND_NOT_ALLOWED`, sem chamada REST.
* `mitm_set_map_local` em sessão `mitmdump` (sem bridge web) → `SESSION_NOT_RUNNING`.

### 2.7 E2E-G — Resiliência de ciclo de vida (carga, com o QA)

* Abrir/fechar N=20 sessões `mitmdump` concorrentes em portas efêmeras; ao final, **0 portas em `LISTEN`** e **0 processos órfãos** (`ps` filtrado pelo argv), com `session_list` vazio.
* Matar o subprocesso por fora (SIGKILL) e verificar que `session_status` transita para `FAILED` e as portas são liberadas.
* Forçar `PORT_IN_USE` ocupando a porta antes do start e confirmar o código de erro correto.

---

## 3. Carga e Estresse (Dev QA · Command Code)

| Métrica | Meta | Método |
| :--- | :--- | :--- |
| Vazamento de portas | 0 após teardown | `ss -ltn` antes/depois de 20 ciclos |
| Processos órfãos | 0 | varredura de `ps` por argv do subprocesso |
| Handshake XSRF determinístico | 100% | N repetições de `PUT /options` (já observado 6/6 e 3/3) |
| Sessões concorrentes | sem deadlock, teardown limpo | `asyncio.gather` de starts/stops |
| Cobertura de testes | ≥ 85% (meta do plano) | `pytest --cov=mcp_security_mitmproxy` |

Nota de arquitetura para o QA: o gargalo esperado não é CPU, é **leasamento de porta** (`core/session.py`) e o **boot do tornado** do mitmweb. Os cenários de estresse devem medir o tempo de `start` e `stop` separadamente e afirmar o teardown, não apenas o sucesso do start.

---

## 4. Requisitos de Segurança R1–R5 (Sec · OpenCode #3)

| Req. | Verificação de aceite | Onde |
| :--- | :--- | :--- |
| R1 | `web_host` default `127.0.0.1`; `binds_publicly` falso por default | `test_server.py` (já coberto), `Settings` |
| R2 | token web nunca no argv; entregue via config `0600`; output não ecoa `web_password` | inspeção de argv + `MitmwebStartOutput` |
| R3 | paths por `ensure_allowed`; 8 opções reservadas; comandos por allowlist | `test_paths.py`, `test_tool_conformance.py` |
| R4 | `redact=True` por default em detail/export | `test_redact.py`, E2E-A/E2E-E |
| R5 | `local`/`tun` falham explicitamente, sem escalar privilégio | `test_modes.py` |

---

## 5. Handoff e ordem de execução

1. **Backend (OpenCode #2)** — implementar `tests/integration/test_e2e_traffic.py` (E2E-A…E) e `tests/integration/test_rules_live.py`; rodar `uv build` limpo. Reutilizar o fixture `mitmweb_instance` já existente e o bootstrap XSRF do `MitmwebClient`.
2. **QA (Command Code)** — E2E-G + estresse + cobertura; validar a matriz de conformidade (gate `test_tool_conformance.py`).
3. **Sec (OpenCode #3)** — checklist R1–R5 e parecer de Go-Live.
4. **Documentação (Antigravity #2)** — ADR-0004, incluindo a decisão A-1.

**DoD da Fase 5:** gate de conformidade verde, cenários E2E verdes, 0 vazamentos sob carga, R1–R5 com evidência, `uv build` sem erro e parecer de segurança emitido.
