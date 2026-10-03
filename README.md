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

## Defence — ingress policy prototype

Separate Defence flow demonstrates the reverse boundary: `policies/defence-ingress.yaml` authorizes signed inbound actions before the request reaches OpenShell. A denied action is audited and quarantines only that source; an allowed action is sent to its assigned OpenShell sandbox. The OpenShell policies in `policies/defence-sensor-*.yaml` remain the secondary containment layer for handler filesystem and egress.

See [`defence/README.md`](defence/README.md) for setup and the demo sequence. This path no longer uses `demo_action` or an outbound POST as its ingress-denial example.