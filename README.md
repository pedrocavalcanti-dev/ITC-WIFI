# ITC Wi-Fi Auth

Backend do AUTHITC, portal de autenticação Wi-Fi do laboratório ITC Educacional.
Stack: Python 3.11+, Django 5.2 e SQLite. A produção futura usará Debian 12,
Gunicorn e Nginx; a implantação ainda não está configurada.

## Desenvolvimento no Windows

Execute na raiz do projeto:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Crie `.env` usando `.env.example` e substitua `DJANGO_SECRET_KEY` por uma chave
aleatória. Se `.env` já existir, preserve sua configuração. Para gerar uma chave:

```powershell
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

```powershell
python .\app\gerenciar.py migrate
python .\app\gerenciar.py createsuperuser
python .\app\gerenciar.py runserver
```

Abra http://127.0.0.1:8000/. O painel `/painel/` exige usuário staff;
`/admin/` usa o admin do Django. Cadastro pede apenas usuário e senha e faz login
automático. Bloqueio Wi-Fi não desativa o User Django.

Em Linux, ative com `source .venv/bin/activate` e use `python app/gerenciar.py`.
`requirements-prod.txt` adiciona Gunicorn para a fase de implantação.

## Configuração e estrutura

O `.env` é carregado da raiz. `DJANGO_DEBUG` aceita `1`, `true`, `yes` e `on`
(sem distinção entre maiúsculas/minúsculas); hosts e origens CSRF aceitam CSV.
`DJANGO_SECRET_KEY` é obrigatória. O SQLite fica em `app/db.sqlite3`;
`DJANGO_DB_PATH` pode apontar para outro arquivo SQLite, com caminhos relativos
resolvidos a partir da raiz do projeto.

```text
AUTHITC/
├── .env.example, .gitignore, README.md
├── requirements.txt, requirements-prod.txt
├── templates/                 # três HTML temporários, sem CSS/JS
├── static/{css,js,img}/       # diretórios reservados
├── media/                    # arquivos enviados futuramente
└── app/
    ├── gerenciar.py, db.sqlite3
    ├── config/
    └── apps/portal/           # backend, testes e migrations
```

`collectstatic` usará `staticfiles/` na raiz. Templates, static e media ficam
fora de `app/`. `.env`, banco local e arquivos de media não devem ser versionados.

## Sessões e integração futura

`services.py` expõe `AuthResult`, `get_client_ip`, `normalize_mac`,
`authorize_client` e `revoke_client`. A autorização atual registra apenas o
estado local; não libera tráfego em um AP. A integração com captive portal/AP
será implementada posteriormente, nos pontos `FUTURE` dos serviços.

Sem MAC, a sessão pode existir sem Dispositivo. Com MAC, o dispositivo é
atualizado e a sessão anterior daquele MAC é encerrada; sem MAC, isso ocorre
para a mesma combinação usuário/IP. Clientes distintos podem ter sessões
simultâneas. Revogação sem filtros e logout encerram todas as sessões Wi-Fi do
usuário; bloqueio pelo painel ou admin também encerra essas sessões.
`autorizada` registra a autorização concedida na abertura; `ativa` indica se
a sessão continua aberta. Desbloquear não reabre sessões.

O IP informado por `X-Forwarded-For` é validado e usado como metadado, com
fallback para `REMOTE_ADDR`. Na implantação, Nginx deverá sobrescrever os
headers encaminhados e impedir acesso direto ao backend antes que esse IP
seja usado na integração real. Não há descoberta de MAC nem parâmetros de
redirecionamento externos neste backend.

O signal cria PerfilWifi para novos usuários; os fluxos de autenticação e
serviços também criam o perfil quando necessário para usuários preexistentes.
O painel evita consultas por usuário usando `select_related`.

## Validação

```powershell
python .\app\gerenciar.py check
python .\app\gerenciar.py makemigrations --check
python .\app\gerenciar.py test
```

Os testes verificam cadastro, hashing, validadores, sessões, logs, bloqueios,
permissões staff, métodos HTTP, CSRF e consultas do painel. Não dependem de
frontend final ou equipamentos de rede.
O runner em `app/config/test_runner.py` usa `apps` como descoberta padrão para
que o comando sem rótulos encontre os testes quando executado da raiz;
rótulos explícitos do Django continuam funcionando.

## Rede futura

- Servidor: `auth01`
- Rede interna: `10.10.0.20`
- Administração: `10.53.52.69`
- Gateway/DNS interno: `10.10.0.1`

Sem Docker, PostgreSQL, Redis, Celery, RADIUS, firewall ou APIs externas nesta fase.
