# Defence — MVP: ingress policy i containment exploita

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
- Zdarzenie zawiera `action`, `sensor_id`, `event_id` i `vendor_document`. Demo parsera celowo używa podatnego `yaml.unsafe_load`; nigdy nie używaj go w prawdziwym systemie.
- Stały payload YAML próbuje odczytać syntetyczny canary, wysłać go do lokalnego kolektora oraz nadpisać syntetyczny plik nastawy.
- OpenShell jest warstwą containment po ingress: polityka ogranicza pliki i egress, a sandbox ma limit 1 CPU i 256 MiB RAM.
- Kwarantanna i audyt są przechowywane w lokalnym SQLite (`var/defence.db`), więc przetrwają restart procesu. To nadal pojedynczy lokalny plik, nie współdzielony ani wysoko dostępny store.
- `POST /admin/sources/{source}/unquarantine` wymaga `DEFENCE_ADMIN_TOKEN` jako Bearer tokenu i zapisanego powodu przeglądu; operacja trafia do audytu.
- `/events` pokazuje audyt, stan kwarantanny oraz liczniki dozwolonych, zablokowanych i skompromitowanych zdarzeń.

## Demo

1. Lokalny wariant uruchamia ten sam parser i payload poza OpenShell. Powinien odczytać syntetyczny canary, wysłać jego bajty do lokalnego kolektora i zmienić nastawę z `40` na `9999`.
2. Wariant OpenShell wysyła exploit jako dozwolone, poprawnie podpisane `telemetry.read`. Parser zostaje skompromitowany, ale polityka sandboxa ma zablokować odczyt chronionych plików, egress i zapis nastawy.
3. Gateway raportuje containment i kwarantannuje źródło po wykryciu kompromitacji. Niedozwolona akcja nadal jest blokowana wcześniej przez ingress.
4. `sensor-b` ma niezależny sandbox i pozostaje aktywny.

## Kryteria ukończenia

- Niedozwolona akcja jest blokowana przez politykę ingress bez wywołania OpenShell.
- Dozwolona akcja jest przekazywana wyłącznie do sandboxa przypisanego temu źródłu.
- Sandbox demonstruje ograniczenia filesystem i egress po dopuszczeniu requestu przez ingress.
- Po odmowie ingress jedno źródło jest kwarantannowane, a drugie działa dalej.
- Log nie zawiera surowego payloadu ani sekretów.
- Testy obejmują poprawny odczyt, deny, kwarantannę, izolację źródeł i błędny podpis.

## Poza zakresem

Rzeczywiste podłączenie do SCADA, sterowanie urządzeniami, działanie w infrastrukturze produkcyjnej, trwała baza stanu, konfiguracja wielu tenantów oraz automatyczne tworzenie sandboxów na każde źródło.

Projekt używa wyłącznie syntetycznych danych demonstracyjnych. Nie wolno podłączać go do systemów operacyjnych ani przesyłać prawdziwych sekretów.
Ostrożne mapowanie przykładu na wodociąg, IEC 62443, MITRE ATT&CK for ICS i NIS2 znajduje się w [SCENARIO.md](SCENARIO.md); nie jest to deklaracja zgodności.

## Uruchomienie lokalnego demo

Wymagane: działający Docker-backed OpenShell gateway, Docker i środowisko z `uv`. Polecenia `openshell` należy wykonać w terminalu zgodnym z konfiguracją Twojego POC.

Z katalogu głównego repozytorium:

```shell
docker build -t reverseopenshell-runner:dev .
uv sync
sh scripts/create-defence-sandboxes.sh
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEFENCE_SENSOR_B_SECRET='demo-sensor-b'
export DEFENCE_ADMIN_TOKEN='local-demo-operator-token'
export OPENSHELL_GRPC_ENDPOINT='127.0.0.1:8080'
uv run uvicorn defence.app.main:app --port 8001
```

Skrypt tworzy dwa sandboxy przed rozpoczęciem obsługi ruchu; nie tworzy nowego sandboxa dla każdego zdarzenia. Sandbox utworzony przed zmianą obrazu/polityki nie aktualizuje się sam. Użyj nowych nazw lub odtwórz stare dopiero po sprawdzeniu, że nie zawierają potrzebnego stanu.
Override endpointu jest potrzebny, gdy aktywny gateway ma adres `host.docker.internal`, który działa z kontenerów, ale nie rozwiązuje się na hoście macOS.
Obraz ustawia `/workspace` jako katalog roboczy zapisywalny przez UID 1000. Pliki handlerów w `/app` są jawnie czytelne dla tego UID, a polityka traktuje ten katalog jako read-only.

Podpisz surowe body HMAC-SHA256 w formacie `sha256=<hex>` i przekaż je w nagłówku `x-hook-signature`. Przykład dozwolonego odczytu:

```shell
BODY='{"action":"telemetry.read","sensor_id":"A-01","event_id":"evt-001","vendor_document":"flow_lpm: 7.25\n"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

## Porównanie exploita

Uruchom API z tokenem testowego kolektora (po wcześniejszym zatrzymaniu poprzedniego procesu API):

```shell
export DEMO_EXFIL_TOKEN='local-demo-collector-token'
export DEMO_EXFIL_URL='http://host.openshell.internal:9999/collect'
uv run uvicorn defence.app.main:app --port 8001
```

W drugim terminalu:

```shell
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEMO_EXFIL_TOKEN='local-demo-collector-token'
export OPENSHELL_GRPC_ENDPOINT='127.0.0.1:8080'
DEMO_BENCHMARK_TRIALS=20 uv run python scripts/compare-defence-exploit.py
```

Skrypt mierzy 20 lokalnych baseline’ów i 20 uruchomień już działającego sandboxa, a następnie wysyła jeden podpisany request przez gateway, aby sprawdzić kwarantannę. Raportuje zmierzone p50/p95 dla tych uruchomień. To benchmark jednego syntetycznego payloadu, nie 20 różnych klas ataków ani wynik reprezentatywny dla produkcji.

Baseline powinien wykazać odczyt canary, bajty otrzymane przez lokalny kolektor i nastawę `9999`. Dla sandboxa wymagaj zablokowanego odczytu i zapisu oraz `collector_received_bytes: 0`. Sprawdź logi OpenShell, by potwierdzić przyczynę odmowy egress; sam brak danych w kolektorze jej nie dowodzi. Nie używaj prawdziwych sekretów ani zdalnego kolektora.

Przykład niedozwolonej akcji ingress:

```shell
BODY='{"action":"telemetry.write","sensor_id":"A-01","event_id":"evt-denied","vendor_document":"flow_lpm: 7.25\n"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

Oczekiwany wynik niedozwolonej akcji: HTTP 403, `source quarantined`, bez uruchomienia handlera. Po kwarantannie `sensor-a` sprawdź, że `sensor-b` nadal przyjmuje podpisane `telemetry.read`. `/events` pokazuje aktywne i quarantined źródła oraz liczbę zablokowanych żądań ingress.

Po ręcznym sprawdzeniu źródła można je zwolnić. Użyj silnego, lokalnego tokenu zamiast przykładowej wartości:

```shell
curl -sS -X POST http://127.0.0.1:8001/admin/sources/sensor-a/unquarantine \
  -H "authorization: Bearer $DEFENCE_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"reason":"Reviewed synthetic incident and rotated source key."}'
```

Demo nie ma identity provider ani ról operatorów. Nie udostępniaj tego endpointu poza lokalnym środowiskiem testowym.
