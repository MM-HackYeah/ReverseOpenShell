# Plan implementacji — Goldman Sachs AI Control Layer

## Cel MVP

Zademonstrować warstwę pośredniczącą, która kontroluje wywołania narzędzi agenta, egzekwuje polityki centralne, ogranicza zasoby i udostępnia testowalne raportowanie. Izolowany runner i audyt mają korzystać ze wspólnego rdzenia; zakres agentowy i budżetowy jest specyficzny dla tego wyzwania.

## Zależność od wspólnego rdzenia

Plan zakłada działający kontrakt polityk, decyzji (`allow`, `deny`, `redact`), izolowanego wykonania i audytu z `common/README.md` oraz pionowy wycinek Defence opisany w `defence/PLAN.md`. Nie należy czekać na rozbudowany produkt Defence: wystarczy stabilny interfejs i testy kontraktowe.

## Etapy

### 1. Zdefiniować minimalny przepływ agenta

- Jeden agent demonstracyjny oraz dwa narzędzia: jedno bezpieczne (np. wyszukanie w katalogu demo) i jedno uprzywilejowane, które ma wymagać jawnej reguły.
- Agent i narzędzia działają lokalnie lub są deterministycznie mockowane; brak wymagania płatnego API.
- Każde wywołanie narzędzia przechodzi przez Control Layer, bez bezpośredniego dostępu agenta do narzędzia.

**Warunek wyjścia:** architektura pokazuje, że nie ma ścieżki omijającej policy engine.

### 2. Rozszerzyć model polityk

- Zdefiniować reguły dla nazw narzędzi, parametrów, modeli dozwolonych i endpointów sieciowych.
- Dodać limity wywołań oraz prosty limit kosztu/tokenów lub jednostek demonstracyjnych.
- Wprowadzić zachowania `allow`, `deny` i `redact` oraz bezpieczną decyzję domyślną.
- Obsłużyć błędną konfigurację i zmianę polityki w czasie działania.

**Warunek wyjścia:** testy dowodzą, że zmiana polityki zmienia decyzje kolejnych wywołań.

### 3. Wpiąć agenta i kontrolę narzędzi

- Przechwytywać żądanie narzędzia przed wykonaniem.
- Walidować schemat i parametry, stosować allowlisty oraz reguły wykrywania demonstracyjnego sekretu.
- Uruchamiać zatwierdzone akcje przez wspólny runner, z ograniczonym dostępem do plików i sieci.
- Zwracać agentowi kontrolowany wynik lub bezpieczny komunikat o odmowie.

**Warunek wyjścia:** agent może wykonać dozwolone narzędzie, ale nie może ominąć blokady przez zmianę treści promptu.

### 4. Dodać budżet, audyt i dashboard

- Egzekwować licznik wywołań i limit zasobów/kosztu, a nie tylko wyświetlać ich wartości.
- Rejestrować użytkownika/aktora demonstracyjnego, narzędzie, decyzję, przyczynę, czas, wynik oraz zużycie limitu.
- Pokazać ostatnie interakcje, zablokowane próby, wykorzystanie limitów i stan polityk w prostym dashboardzie.
- Nie logować sekretów w postaci jawnej; redagować wrażliwe wartości.

**Warunek wyjścia:** przekroczenie limitu blokuje kolejne działanie i jest widoczne w audycie.

### 5. Przygotować samodzielnie uruchamialne testy

- Dozwolone narzędzie z poprawnymi parametrami.
- Nieznane lub zablokowane narzędzie.
- Sekret w wejściu lub wyjściu: redakcja albo blokada zgodnie z konfiguracją.
- Przekroczony budżet/licznik.
- Próba dostępu runnera do niedozwolonego pliku lub hosta.
- Zmiana polityki w trakcie pracy.

**Warunek ukończenia:** test suite uruchamia się jedną udokumentowaną komendą, zawiera przypadki pozytywne i negatywne i nie wymaga płatnego API.

### 6. Próba oceny i demo

- Uruchomić testy przed prezentacją i przygotować resetowalny stan demo.
- Pokazać legalne wywołanie, prompt injection lub próbę nadużycia, blokadę/redakcję, zdarzenie audytowe i zadziałanie limitu.
- Zmienić konfigurację podczas działania i powtórzyć wywołanie.
- Przygotować krótką informację o ograniczeniach, wydajności i zachowaniu przy błędzie modelu lub narzędzia.

## Kryteria ukończenia

- Centralna konfiguracja zarządza politykami i limitami.
- Każde wywołanie narzędzia przechodzi przez warstwę kontroli.
- Dostępne są kontrole deterministyczne oraz co najmniej jeden pokazany mechanizm semantyczny, jeśli można go uruchomić lokalnie i niezawodnie.
- Budżety i ograniczenia wykonania są egzekwowane.
- Dashboard/logi prezentują zdarzenia dla zespołów bezpieczeństwa.
- Automatyczne testy pozytywne i negatywne przechodzą.

## Ryzyka i ograniczenia

- Kontrola semantyczna AI jest probabilistyczna; nie może być jedyną blokadą.
- Agentowy framework nie powinien być przedmiotem projektu; oceniana jest warstwa kontroli.
- Koszt/tokeny w demie mogą być jednostkami symulowanymi, ale muszą być jawnie oznaczone jako takie.
- Szczegółowy opis wyzwania i regulamin podają różne wagi dwóch kryteriów końcowych. Warto potwierdzić obowiązujący podział u organizatora.

## Kolejność względem Defence

Zacząć po ustabilizowaniu wspólnych interfejsów i demonstracji izolowanego wykonania w Defence. Ponownie wykorzystać runner, decyzje polityk i audyt, ale nie próbować przerabiać całego rozwiązania Defence na platformę agentową przed działającym prototypem.
