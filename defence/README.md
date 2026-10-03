# Defence — MVP: polityki ingress i izolacja handlerów

## Problem i użytkownik

Operator infrastruktury krytycznej przyjmuje dane od zewnętrznych dostawców, np. zdarzenia z czujników. Błąd lub przejęcie handlera jednego źródła nie powinny umożliwić dostępu do sekretów ani zatrzymać obsługi pozostałych źródeł.

## Przepływ

```text
Czujnik → weryfikacja podpisu → polityka ingress → sandbox OpenShell → handler
                                  └ deny → kwarantanna + audyt
Pozostałe źródła ───────────────────────────────────────────────→ działają dalej
```

## Zakres MVP

- `POST /sensor/{source}` przyjmuje ustandaryzowane zdarzenie JSON.
- Dwa źródła demonstracyjne: `sensor-a` i `sensor-b`; każde mapuje się na własny, wcześniej utworzony sandbox.
- Centralna polityka ingress w `policies/defence-ingress.yaml` ma `default_decision: deny`, definiuje sekrety HMAC, sandbox i dozwolone akcje dla każdego źródła.
- Podpis HMAC jest weryfikowany przed autoryzacją. Błędny podpis jest odrzucany, nie uruchamia handlera i nie powoduje kwarantanny uwierzytelnionego źródła.
- Dla MVP oba źródła mogą wyłącznie żądać `telemetry.read`. Niedozwolona akcja jest odrzucana na ingress przed wywołaniem OpenShell, zapisywana w audycie i kwarantannuje źródło.
- Handler wykonuje się przez OpenShell Python SDK w sandboxie przypisanym do źródła.
- Zdarzenie zawiera `action`, `sensor_id`, `event_id` i `flow_lpm`.
- OpenShell jest warstwą drugiej linii obrony: ogranicza pliki i sieć procesu handlera po dopuszczeniu żądania przez ingress.
- Kwarantanna jest lokalnym stanem w pamięci procesu; resetuje się po restarcie. To wystarcza do demo, nie jest trwałym mechanizmem produkcyjnym.
- `/events` pokazuje audyt, stan kwarantanny i liczniki dozwolonych oraz zablokowanych żądań ingress.

## Demo

1. `sensor-a` przesyła podpisane `telemetry.read`; polityka ingress dopuszcza akcję i handler przetwarza syntetyczny odczyt.
2. `sensor-a` przesyła poprawnie podpisane, lecz nieautoryzowane `telemetry.write`; gateway odrzuca je **przed uruchomieniem sandboxa**, zapisuje `ingress_action_not_allowed` i kwarantannuje źródło.
3. Kolejne żądanie `sensor-a` jest odrzucane jako quarantined.
4. `sensor-b` nadal może przesyłać dozwolone odczyty.

## Kryteria ukończenia

- Niedozwolona akcja jest blokowana przez politykę ingress bez wywołania OpenShell.
- Dozwolona akcja jest przekazywana wyłącznie do sandboxa przypisanego temu źródłu.
- Polityka OpenShell niezależnie ogranicza egress i filesystem handlera.
- Po odmowie ingress jedno źródło jest kwarantannowane, a drugie działa dalej.
- Log nie zawiera surowego payloadu ani sekretów.
- Testy obejmują poprawny odczyt, deny, kwarantannę, izolację źródeł i błędny podpis.

## Poza zakresem

Rzeczywiste podłączenie do SCADA, sterowanie urządzeniami, działanie w infrastrukturze produkcyjnej, trwała baza stanu, konfiguracja wielu tenantów oraz automatyczne tworzenie sandboxów na każde źródło.

Projekt używa wyłącznie syntetycznych danych demonstracyjnych. Nie wolno podłączać go do systemów operacyjnych ani przesyłać prawdziwych sekretów.

## Uruchomienie lokalnego demo

Wymagane: działający Docker-backed OpenShell gateway, Docker i środowisko z `uv`. Polecenia `openshell` należy wykonać w terminalu zgodnym z konfiguracją Twojego POC.

Z katalogu głównego repozytorium:

```shell
docker build -t reverseopenshell-runner:dev .
uv sync
sh scripts/create-defence-sandboxes.sh
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEFENCE_SENSOR_B_SECRET='demo-sensor-b'
export OPENSHELL_GRPC_ENDPOINT='127.0.0.1:8080'
uv run uvicorn defence.app.main:app --port 8001
```

Skrypt tworzy dwa sandboxy przed rozpoczęciem obsługi ruchu; nie tworzy nowego sandboxa dla każdego zdarzenia.
Override endpointu jest potrzebny, gdy aktywny gateway ma adres `host.docker.internal`, który działa z kontenerów, ale nie rozwiązuje się na hoście macOS.
Obraz ustawia `/workspace` jako katalog roboczy zapisywalny przez UID 1000. Pliki handlerów w `/app` są jawnie czytelne dla tego UID, a polityka traktuje ten katalog jako read-only.

Podpisz surowe body HMAC-SHA256 w formacie `sha256=<hex>` i przekaż je w nagłówku `x-hook-signature`. Przykład dla dozwolonego odczytu:

```shell
BODY='{"action":"telemetry.read","sensor_id":"A-01","event_id":"evt-001","flow_lpm":7.25}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

Przykład niedozwolonej akcji ingress:

```shell
BODY='{"action":"telemetry.write","sensor_id":"A-01","event_id":"evt-denied","flow_lpm":7.25}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

Oczekiwany wynik niedozwolonej akcji: HTTP 403, `source quarantined`, bez uruchomienia handlera. Po kwarantannie `sensor-a` sprawdź, że `sensor-b` nadal przyjmuje podpisane `telemetry.read`. `/events` pokazuje aktywne i quarantined źródła oraz liczbę zablokowanych żądań ingress.
