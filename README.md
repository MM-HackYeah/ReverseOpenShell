# ReverseOpenShell

Minimalne MVP dla wyzwania **Goldman Sachs AI Control Layer**. Projekt przyjmuje webhooki od zewnętrznych integracji, przypisuje im maksymalny poziom zaufania, opcjonalnie obniża go na podstawie klasyfikacji lokalnym LLM, a następnie uruchamia request w istniejącym sandboxie OpenShell.

## Zakres

- Trzy wcześniej utworzone sandboxy: `untrusted`, `readonly`, `write`.
- Gateway FastAPI: `POST /hook/{source}`.
- Klasyfikacja nie może podwyższyć zaufania ponad skonfigurowany limit źródła.
- Podpis HMAC źródła; brak lub błędny sekret oznacza poziom `untrusted`.
- Izolowane wykonanie przez `openshell sandbox exec`, log audytowy JSONL i endpoint do jego odczytu.
- Opcjonalna klasyfikacja przez lokalne Ollama. Bez modelu działają reguły deterministyczne; błąd klasyfikatora obniża poziom do `untrusted`.

## Uruchomienie

Wymagane: Python 3.11+, `uv`, Docker oraz skonfigurowany lokalny gateway OpenShell. W katalogu repo:

```shell
docker build -t reverseopenshell-runner:dev .
uv sync
sh scripts/create-sandboxes.sh
export DEMO_READONLY_SECRET='local-demo-readonly'
export PARTNER_WRITE_SECRET='local-demo-write'
uv run uvicorn goldmansachs.app.main:app --reload
```

Sekrety powyżej są wyłącznie przykładowymi wartościami do lokalnego demo. Nie używaj ich poza nim.

Wyślij podpisany, dozwolony request:

```shell
BODY='{"url":"https://api.github.com/zen","method":"GET"}'
SIGNATURE=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEMO_READONLY_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8000/hook/demo-readonly \
  -H "content-type: application/json" \
  -H "x-hook-signature: sha256=$SIGNATURE" \
  --data "$BODY"
```

Sprawdź `/docs`, `/health` i `/events`. Ustaw `OLLAMA_MODEL` (oraz opcjonalnie `OLLAMA_URL`) aby włączyć klasyfikację semantyczną przez lokalny Ollama. Python SDK łączy się z aktywnym gatewayem wybranym przez OpenShell CLI.

## Bezpieczeństwo i ograniczenia

OpenShell egzekwuje ograniczenia systemu plików i sieci wewnątrz sandboxa; gateway nie traktuje samej klasyfikacji LLM jako kontroli dostępu. Demo nie przyjmuje dowolnego kodu od requestu i nie udostępnia kluczy zewnętrznych. Sandbox `write` dopuszcza tylko `POST` do przykładowego endpointu `postman-echo.com/post`, bez sekretów. Integracja z providerem credential OpenShell nie jest częścią tego minimalnego MVP.

W produkcji potrzebne byłyby m.in. uwierzytelnianie źródeł z właściwym zarządzaniem sekretami, trwały audyt, rate limiting, ochrona przed replay, bezpieczne zarządzanie sandboxami i walidacja zagrożeń operacyjnych.

## Defence — ingress policy and post-ingress containment

Separate Defence flow demonstrates two distinct controls: `policies/defence-ingress.yaml` authorizes signed inbound actions before the request reaches OpenShell, then OpenShell confines the deliberately vulnerable YAML parser after an allowed request enters its sandbox. The synthetic exploit compares an unconfined baseline with the sandbox for access to a canary file, egress to a local-only collector, and a write to a synthetic setpoint. A parser compromise triggers source quarantine.

The parser intentionally uses `yaml.unsafe_load` and is exploit-vulnerable by design. Never deploy it or connect the demo to real infrastructure. Run the repeatable local benchmark with `uv run python scripts/bench-defence.py --trials 20`; it saves per-trial JSON under ignored `var/`. [`defence/EXPERIMENTS.md`](defence/EXPERIMENTS.md) records experiments and limits, and [`defence/README.md`](defence/README.md) has setup instructions and one measured run. SQLite persists audit/quarantine state; the local operator-token endpoint records unquarantine reasons. [`defence/SCENARIO.md`](defence/SCENARIO.md) gives conceptual standards mappings, not a compliance assessment.

See [`defence/README.md`](defence/README.md) for setup, comparison, and limitations.