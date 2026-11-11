# gh-bridge

Ponte entre o seu terminal e o **GitHub Actions**: você dispara um comando local,
ele executa no runner do GitHub e o resultado (stdout, stderr, exit code) volta
para a sua máquina.

```
┌────────────────────┐   1. POST /repos/{repo}/dispatches (token do gh)   ┌──────────────────────────────┐
│  seu terminal      │ ────────────────────────────────────────────────▶ │  GitHub Actions              │
│  gh-bridge run …   │     payload = comando + HMAC (a chave NÃO vai)     │  bridge.yml                  │
│                    │                                                    │   1. verify  (HMAC, ±5 min)  │
│                    │   4. artifact bridge-result-<nonce>                │   2. execute (bash -lc)      │
│                    │ ◀──────────────────────────────────────────────── │   3. upload artifact         │
│  3. poll de runs   │                                                    └──────────────────────────────┘
│     e artifacts    │   2. run-name = "bridge · <nonce>"
└────────────────────┘
```

O `ngrok` **não** é necessário para mandar comandos: o GitHub já te dá um
endpoint HTTPS autenticado (`repository_dispatch`). Ele só é usado em dois
modos opcionais, explicados abaixo: o **callback** (resultado em tempo real na
sua máquina) e a **sessão** (um link público temporário no runner).

---

## 1. O que tem aqui

| Arquivo | Papel |
| --- | --- |
| `.github/workflows/bridge.yml` | Pipeline principal: recebe `repository_dispatch`, valida a assinatura, executa o comando, publica o artifact e o summary |
| `.github/workflows/bridge-session.yml` | Modo sessão opcional: sobe um túnel ngrok no runner e aceita comandos assinados por alguns minutos |
| `bridge/` | Pacote Python (só stdlib) usado tanto na sua máquina quanto no runner |
| `bridge/cli.py` | CLI `gh-bridge` (init, doctor, run, listen, session + comandos internos do runner) |
| `bridge/crypto.py` | HMAC-SHA256, janela de tempo, assinatura de corpo HTTP |
| `bridge/payload.py` | Envelope do `client_payload` (comando em base64, nonce, assinatura) |
| `bridge/executor.py` | Execução com timeout, captura de saída, redação de segredos e truncamento |
| `bridge/gh.py` | Cliente REST do GitHub (dispatch, runs, artifacts, logs) |
| `bridge/server.py` | Receptor local do callback assinado |
| `bridge/session.py` | Servidor de sessão no runner + cliente |
| `bridge/tunnel.py` | ngrok / cloudflared |
| `tests/` | 54 testes (unitários + integração local de HTTP) |

---

## 2. Começo rápido

### 2.1 Criar o repositório público e subir os arquivos

```powershell
# na pasta deste projeto
gh repo create gh-bridge --public --source . --remote origin --push
```

> A pipeline precisa estar **no branch default** (`main`): `repository_dispatch`
> só encontra workflows que existem lá.

Se preferir criar o repo vazio e subir depois:

```powershell
gh repo create gh-bridge --public
git init; git add .; git commit -m "gh-bridge"
git branch -M main
git remote add origin https://github.com/<seu-usuario>/gh-bridge.git
git push -u origin main
```

### 2.2 Instalar a CLI

```powershell
pip install -e .
# ou, sem instalar nada:
python -m bridge --help
```

### 2.3 Configurar a chave e o segredo do repositório

```powershell
gh-bridge init --repo <seu-usuario>/gh-bridge
```

O `init`:

1. gera uma chave aleatória em `~/.gh-bridge/key` (permissão 600);
2. grava a mesma chave como **secret `BRIDGE_KEY`** no repositório, via
   `gh secret set` (sem passar a chave pela linha de comando);
3. grava `~/.gh-bridge/config.json` com o repo padrão.

Se você já tem uma chave e quer só rotacionar: `gh-bridge init --rotate`.

A pasta de configuração é `~/.gh-bridge` por padrão. Para apontar para outro
lugar (útil em sandbox/CI local), defina `BRIDGE_HOME`:

```powershell
$env:BRIDGE_HOME = "D:\work\.gh-bridge"
gh-bridge init --repo <seu-usuario>/gh-bridge
```

### 2.4 Conferir

```powershell
gh-bridge doctor
```

Ele checa token, acesso ao repo, se o `bridge.yml` está no branch default, se o
secret `BRIDGE_KEY` existe e se o ngrok está instalado.

### 2.5 Rodar o primeiro comando

```powershell
gh-bridge run -- "python -V && echo hello from GitHub && uname -a"
```

Saída esperada:

```
dispatched nonce 6e77017665e74a78 to ZyamHunter/gh-bridge
run 123456789: https://github.com/ZyamHunter/gh-bridge/actions/runs/123456789
  status: queued
  status: in_progress
  status: completed/success

status  : OK
duration: 4.21s
run     : https://github.com/ZyamHunter/gh-bridge/actions/runs/123456789
--- stdout ---
Python 3.12.8
hello from GitHub
Linux runnervm... 6.8.0-1018-azure #18-Ubuntu ...
```

O exit code do `gh-bridge run` é o **exit code do comando remoto** (bom para
usar em scripts/CI local).

Para rodar seus testes:

```powershell
gh-bridge run -- "pytest -q"
gh-bridge run -- "npm ci && npm test -- --watch=false"
gh-bridge run --json -- "pytest -q" | ConvertFrom-Json
```

---

## 3. Como a chave é protegida

O ponto central: **a chave nunca é enviada**. O que viaja no trigger é uma
assinatura HMAC de curta duração, calculada sobre o comando exato.

```
payload = {
  "v": "v1",
  "ts": 1794437103,              # época em segundos
  "nonce": "6e77017665e74a78",   # correlação do run
  "cmd_b64": "cHl0ZXN0IC1x",     # comando em base64 (multi-linha/UTF-8)
  "callback": "",                # URL opcional de retorno
  "sig": "6da8c6c8…"             # HMAC-SHA256(chave, "v1\nts\nnonce\ncmd_b64\ncallback")
}
```

Na pipeline:

1. `verify` recalcula o HMAC com `secrets.BRIDGE_KEY` e compara em tempo
   constante (`hmac.compare_digest`);
2. rejeita `ts` fora da janela de **±300 s** (limita replay);
3. a assinatura entra em `::add-mask::` antes de qualquer output — mesmo que
   algum passo ecoe o payload, o valor aparece como `***`;
4. o comando executado **não vê** `BRIDGE_KEY`, `GITHUB_TOKEN`, `GH_TOKEN` nem
   os tokens internos do runner (`executor.child_env()` remove tudo);
5. a saída do comando é **redigida** contra a chave antes de ser gravada.

O que ainda é verdade e você deve saber:

- quem tem **write no repositório** pode disparar `repository_dispatch` — a
  chave não é o único controle de acesso, o token do GitHub é o principal;
- a assinatura é reutilizável dentro da janela de 5 minutos (replay gera uma
  execução duplicada). Se isso importar, reduza `MAX_SKEW_SECONDS` em
  `bridge/crypto.py` ou habilite a allowlist;
- payloads de `repository_dispatch` ficam armazenados no evento do run e são
  visíveis para administradores do repo. Por isso a chave não vai nele.

---

## 4. Modos de uso

### 4.1 `run` — um comando por dispatch (recomendado)

```powershell
gh-bridge run --repo owner/repo -- "pytest -q"
gh-bridge run --no-wait -- "make build"     # dispara e sai
gh-bridge run --wait-timeout 3600 -- "npm test"
```

Cada comando = um run. O resultado vem pelo artifact `bridge-result-<nonce>`,
que a CLI baixa e imprime.

### 4.2 Callback — resultado em tempo real na sua máquina

Aqui o runner te chama de volta. Precisa de um túnel local (ngrok ou
cloudflared):

```powershell
# terminal 1
gh-bridge listen --port 8787

# terminal 2
gh-bridge run --callback https://xxxx.ngrok-free.app/bridge/result -- "pytest -q"
```

O callback é um POST JSON assinado com `X-Bridge-Timestamp` +
`X-Bridge-Signature` (HMAC sobre o corpo). O receptor local valida a assinatura
e a janela de tempo; sem isso, ninguém consegue injetar resultados falsos.

### 4.3 `session` — o link ngrok no runner (o "shell remoto" temporário)

Este é o modo literal que você descreveu: a pipeline sobe um túnel e aceita
comandos por alguns minutos.

```powershell
gh secret set NGROK_AUTHTOKEN --repo owner/repo   # uma vez
gh-bridge session --repo owner/repo --ttl 600
```

```
session url: https://1a2b-3c4d.ngrok-free.app
session healthy: {"ok": true, "commands": 0, ...}
interactive session - type a command, ':quit' to leave
bridge> pytest -q
...
bridge> :quit
```

Como funciona: `bridge-session.yml` roda `session-serve`, que sobe o túnel,
publica a URL no artifact `session-url-<nonce>` (a CLI faz poll até aparecer) e
serve `POST /exec` com comandos assinados.

Limites de segurança embutidos:

- TTL padrão de 600 s (máx. pelo `timeout-minutes: 45` do job);
- no máximo 50 comandos por sessão;
- encerra sozinho após 180 s sem atividade;
- cada requisição expira em 120 s e não pode ser repetida (nonce);
- mesma allowlist, timeout e redação do modo `run`;
- o job tem `permissions: contents: read`.

> **Atenção:** `ngrok` grátis permite **um** agente simultâneo e a URL muda a
> cada sessão. Se você usar o modo callback junto com o modo sessão, vai
> precisar de plano pago ou de `cloudflared` em um dos lados
> (`gh-bridge listen --tunnel cloudflared`, ou `--tunnel cloudflared` no
> `session`).

### 4.4 Manual, pela UI do GitHub

`workflow_dispatch` também está habilitado: Actions → **bridge** → *Run
workflow* → informe o comando. Esse caminho exige write no repo, então é
tratado como confiável (sem HMAC).

---

## 5. Variáveis de repositório (opcionais)

Configure em **Settings → Secrets and variables → Actions → Variables**.

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `BRIDGE_TIMEOUT` | `600` | Timeout do comando, em segundos |
| `BRIDGE_MAX_OUTPUT` | `524288` | Bytes máximos por stream (stdout/stderr), guardando o final |
| `BRIDGE_ALLOWLIST` | vazio | Regex, uma por linha; se preenchida, o comando precisa casar com pelo menos uma |
| `BRIDGE_ECHO_OUTPUT` | `false` | `true` imprime a saída no log do run (veja o aviso abaixo) |
| `BRIDGE_REDACT` | vazio | Segredos extras separados por vírgula, substituídos por `***` |

Exemplo de allowlist só para testes:

```powershell
gh variable set BRIDGE_ALLOWLIST --repo owner/repo --body "^pytest\b`n^npm (ci|test)\b`n^python -m "
```

### Repositório público: log é público

Em repo público, **o log do run é visível para qualquer pessoa**, mas
**artifacts exigem autenticação**. Por isso o padrão é:

- a saída do comando vai **só para o artifact** (`bridge-result-<nonce>`);
- o log mostra apenas exit code, duração e tamanho da saída;
- o summary mostra só metadados.

Se você ligar `BRIDGE_ECHO_OUTPUT=true`, qualquer segredo que o seu teste
imprimir fica público. Ligue apenas sabendo disso.

---

## 6. Segurança e uso aceitável

- Use em um repositório seu. Em repo público, qualquer pessoa vê o workflow e
  os logs; só quem tem write dispara runs.
- A chave vive em dois lugares: `~/.gh-bridge/key` e o secret `BRIDGE_KEY`.
  Rotacione com `gh-bridge init --rotate`.
- O runner é efêmero: nada persiste entre execuções, exceto artifacts (1 dia).
- O job roda com `permissions: contents: read` e sem `persist-credentials`.
- **Não** use isso como compute grátis, mineração ou C2. As *GitHub Actions
  Acceptable Use Policies* proíbem uso abusivo de runners; o desenho aqui é de
  ponte de testes, com TTL curto, orçamento de comandos e allowlist. Mantenha
  assim.

---

## 7. Limitações conhecidas

| Limitação | Detalhe |
| --- | --- |
| Workflow no branch default | `repository_dispatch` não enxerga workflows de outros branches |
| Correlação por `run-name` | O run é achado pelo nonce no título; se você sobrescrever `run-name`, ajuste `find_run` |
| Artifact pode demorar | A CLI tenta por 60 s depois do run terminar |
| Timeout máximo | 30 min no `bridge.yml`, 45 min no `bridge-session.yml` |
| ngrok grátis | 1 agente simultâneo, URL aleatória, precisa de `NGROK_AUTHTOKEN` |
| Windows | A CLI roda em PowerShell; o comando remoto roda em `bash` no Ubuntu |
| Replay em 5 min | Assinatura vale por ±300 s; um replay nessa janela executa de novo |

---

## 8. Solução de problemas

| Sintoma | Causa provável / correção |
| --- | --- |
| `GitHub API 404` no dispatch | Workflow não está no branch default, ou o token não tem escopo `repo` |
| `request accepted` não aparece | Secret `BRIDGE_KEY` ausente no repo → `gh-bridge init` |
| `signature mismatch` | Chave local diferente da do secret → rode `init --rotate` |
| `timestamp is outside …` | Relógio da máquina adiantado/atrasado |
| `no result artifact found` | O comando falhou antes do upload, ou `actions/upload-artifact` quebrou; veja o log do run |
| `no run found for nonce` | O `run-name` do workflow foi alterado, ou o dispatch foi para outro repo |
| `ngrok exited immediately` | Falta `NGROK_AUTHTOKEN` (secret no repo para o modo sessão; `ngrok config add-authtoken` para o modo local) |
| `command rejected by BRIDGE_ALLOWLIST` | Ajuste a variável `BRIDGE_ALLOWLIST` |

---

## 9. Testes

```powershell
python -m unittest discover -s tests -t . -v
```

54 testes cobrindo assinatura, payload, execução, redação, truncamento,
allowlist, cliente REST, callback HTTP e sessão HTTP (tudo local, sem rede).

Simulação do que o runner faz:

```powershell
$env:BRIDGE_KEY = python -m bridge keygen
python scripts/simulate_runner.py            # gera o "client_payload"
# exporte as variáveis BRIDGE_* mostradas e rode:
python -m bridge verify  --out .bridge/request.json
python -m bridge execute --request .bridge/request.json --out .bridge/result.json
python -m bridge summary --request .bridge/request.json --result .bridge/result.json
```
