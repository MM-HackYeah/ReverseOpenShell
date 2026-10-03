# Plan implementacji — Defence

## Cel MVP

Pokazać ingress authorization przed wykonaniem handlera: polityka jawnie dozwala akcje dla podpisanych źródeł, blokuje niedozwolone żądanie zanim dotrze do sandboxa, kwarantannuje źródło, a pozostałe źródła nadal dostarczają syntetyczne odczyty.

## Etapy

### 1. Zamknąć zakres i scenariusz

- Endpoint `POST /sensor/{source}` dla dwóch źródeł demonstracyjnych.
- Jeden typ zdarzenia telemetrycznego JSON oraz jeden kontrolowany handler.
- Przypadek poprawny, błąd podpisu i poprawnie podpisane żądanie akcji spoza ingress allowlist.
- Zapisać jawnie, że prototyp ogranicza ryzyko, ale nie jest certyfikowanym sandboxem ani pełną ochroną przed exploitami.

**Warunek wyjścia:** scenariusz `sensor-a` → ingress deny → kwarantanna, podczas gdy `sensor-b` działa, jest spisany jako test.

### 2. Ustalić interfejs wspólnego rdzenia

- Przyjąć wspólny model żądania, decyzji (`allow`, `deny`, `redact`) i wpisu audytowego opisany w `common/README.md`.
- Ingress policy ma być wersjonowanym plikiem YAML z domyślną decyzją `deny`, listą źródeł, sekretem env, sandboxem oraz dozwolonymi akcjami.
- Handler ma otrzymywać wyłącznie zwalidowane dane potrzebne do obsługi zdarzenia.

**Warunek wyjścia:** przykładowa polityka Defence przechodzi walidację, a niepoprawna konfiguracja zatrzymuje start aplikacji.

### 3. Zaimplementować gateway Defence

- Przyjmować zdarzenie i generować correlation ID.
- Ograniczać rozmiar requestu oraz walidować pola i wartości liczbowe.
- Sprawdzać podpis HMAC przypisany do źródła.
- Autoryzować `action` względem centralnej polityki ingress **przed** wywołaniem OpenShell.
- Nie wykonywać i nie kwarantannować źródła przy błędnym podpisie; przy prawidłowym podpisie i zabronionej akcji odpowiedzieć 403 i odnotować deny.
- Każde źródło mapować na stały sandbox, bez możliwości wyboru sandboxa przez klienta.
- Odrzucać nieznane, niepodpisane i quarantined źródła przed wykonaniem handlera.

**Warunek wyjścia:** request nie może zmienić sandboxa przez payload ani dotrzeć do runnera bez dozwolonej akcji.

### 4. Dodać sandboxy i kontrolowaną próbę nadużycia

- Przygotować osobny sandbox OpenShell na każde źródło (tworzony przed demo, nie per request).
- Każda polityka ma filesystem read-only, minimalny dostęp do `/tmp`, `landlock.compatibility: hard_requirement` i domyślnie brak egress.
- Nie udostępniać klientowi przełącznika symulującego atak ani nieautoryzowanego egressu jako przykładu ingress deny.
- Po ingress deny oznaczać źródło jako quarantined w SQLite; inne źródła zachowują własny stan i sandbox.

**Warunek wyjścia:** test potwierdza, że zabroniona akcja nie wywołuje sandboxa, źródło nie przyjmuje kolejnych requestów, a drugie źródło dalej działa.

### 5. Audyt, prezentacja i testy

- Zapisywać correlation ID, źródło, decyzję, poziom zaufania, powód, czas oraz stan kwarantanny; nie zapisywać body ani kluczy.
- Udostępnić endpoint `/events` z audytem i stanem źródeł.
- Dodać testy poprawnego odczytu, błędnego podpisu, ingress deny przed runnerem, kwarantanny i niezależności źródeł.
- Przygotować skrypt porównawczy: identyczny syntetyczny exploit poza sandboxem oraz w sandboxie; dodatkowo signed attack przez ingress powoduje kwarantannę.

**Warunek ukończenia:** demo działa powtarzalnie od czystego uruchomienia, testy przechodzą, a każda decyzja jest wyjaśnialna w logu.

## Kolejność prac

Najpierw zamknąć przepływ gateway → weryfikacja HMAC → ingress policy → handler w przypisanym sandboxie → audyt. Następnie wykazać, że ingress deny kończy request przed wywołaniem sandboxa i że pozostałe źródło działa dalej. Wystarczy JSON endpoint `/events`, bez dashboardu graficznego.

## Ryzyka i ograniczenia

- Każdy sandbox działa na tym samym compute driverze/gatewayu co istniejący POC; nazwy i workspace są konfigurowalne.
- Kwarantanna i audyt są w lokalnym SQLite; to pojedynczy lokalny store bez HA.
- Exploit comparison ma jeden stały syntetyczny YAML payload, tymczasowy canary, lokalny kolektor i atrapę nastawy. Nie łączy się z realnymi systemami.
- Ingress deny powinien być widoczny w audycie aplikacji; nie przedstawiać go jako zdarzenia `DENIED` OpenShell.
- OpenShell jest drugą warstwą containmentu dla dozwolonego handlera, nie źródłem decyzji ingress.
- Kontener współdzieli jądro; nie deklarować ochrony przed każdym kernel exploitem.

## Następny krok

Pozostałe prace po MVP: wykonać benchmark w działającym OpenShell, rozszerzyć testy do wielu odrębnych bezpiecznych przypadków i zastąpić lokalny operator token właściwym identity/approval w docelowej integracji. Wodociąg/IEC 62443/MITRE/NIS2 są mapowane koncepcyjnie w `SCENARIO.md`, nie jako deklaracja zgodności. POC w `/Users/marcinbodych/Workspace/HackYeah2026/OpenShell` jest źródłem prawdy dla poleceń i zachowania runtime.
