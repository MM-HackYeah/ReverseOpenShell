# HackYeah 2026 — Goldman Sachs: AI Control Layer

## Opis wyzwania

Zbuduj lekką i elastyczną warstwę kontroli dla systemów agentowej AI: agentów, usług MCP, modeli językowych i API. Rozwiązanie ma pomagać organizacjom chronić dane, egzekwować zabezpieczenia, zarządzać budżetami API i blokować ataki, nie spowalniając nadmiernie pracy deweloperów.

Agenci AI mogą uzyskiwać nieuprawniony dostęp do zasobów, podszywać się pod innych aktorów, wykonywać nieodwracalne działania, ulegać prompt injection, ujawniać wrażliwe dane albo zużywać nadmierne zasoby w pętlach autonomicznych. Wyzwanie zakłada kontrolę interakcji w czasie rzeczywistym przez elastyczny pośrednik, łączący deterministyczne reguły z kontrolami semantycznymi opartymi na AI.

## Oczekiwany rezultat

1. **Warstwa kontroli AI** — działający gateway, proxy, middleware, wrapper SDK lub równoważny komponent, który można włączyć do komunikacji aplikacja–agent, agent–agent, agent–MCP albo agent–model.
2. **Przykładowa konfiguracja** — udokumentowany plik polityk pokazujący konfigurowalne poziomy rygoru, reguły budżetowe oraz ustawienia kontroli.
3. **Interaktywny dashboard** — widok kontroli, ogólnej postawy bezpieczeństwa, zablokowanych zagrożeń i metryk, takich jak zużycie zasobów lub koszt.
4. **Uruchamialny zestaw testów** — automatyczne przypadki pozytywne (dozwolone) i negatywne (blokowane lub redagowane), obejmujące m.in. limity budżetowe i ograniczanie exploitów.
5. **Diagram architektury** oraz demonstracja działania warstwy.

Można zbudować własnego agenta lub użyć istniejącego. Ocenie podlega przede wszystkim warstwa kontroli.

## Wymagania funkcjonalne

### Centralny silnik polityk

Jedno źródło konfiguracji powinno zarządzać kontrolami, progami wrażliwości, zachowaniem typu blokuj/redaguj, dozwolonymi modelami LLM oraz limitami zasobów i kosztów.

### Kontrole deterministyczne i semantyczne

- **Deterministyczne:** np. dopasowanie wzorców dla danych osobowych i sekretów, sprawdzanie uwierzytelnienia oraz uprawnień dostępu.
- **Semantyczne:** tam, gdzie to zasadne, wykorzystanie modelu lub innej kontroli AI do oceny znaczenia interakcji.

### Budżety i zasoby

Warstwa powinna umożliwiać egzekwowanie limitów dotyczących m.in. wydatków na komercyjne API, tokenów, czasu obliczeń oraz dostępu do zasobów.

### Ograniczanie znanych ataków

Należy rozważyć wykrywanie lub ograniczanie wzorców znanych exploitów infrastruktury AI, np. złośliwego wykonywania kodu, niebezpiecznej deserializacji i ataków na łańcuch dostaw modeli. Sygnatury mogą pochodzić z zewnętrznie zarządzanego źródła.

### Raportowanie i audyt

Rozwiązanie powinno udostępniać bieżące metryki, takie jak blokowane interakcje i wykorzystanie budżetu, oraz eksportowalne logi audytowe przydatne zespołom bezpieczeństwa.

### Testy własne

Zautomatyzowany zestaw testów ma sprawdzać zarówno prawidłowe, dozwolone zachowania, jak i przypadki, które powinny zostać zablokowane lub zredagowane.

## Walidacja podczas oceny

Sędziowie uruchomią dostarczony zestaw testów i mogą w czasie rzeczywistym zadawać systemowi nieprzygotowane wcześniej prompty. Mogą także zmieniać konfigurację lub źródła sygnatur, aby sprawdzić, jak warstwa reaguje na zmiany reguł, usunięcie kontroli albo zmianę progów. Należy być gotowym pokazać telemetrię wydajności, architekturę, dashboard i logi.

## Technologia i dostępne zasoby

Wybór stosu jest dowolny, m.in. Go, Rust lub Python; można też użyć istniejących narzędzi open source, z uwzględnieniem ich licencji. Dla agentów, modeli i aplikacji można wykorzystać istniejące komponenty.

Wyzwanie nie zapewnia gotowych zbiorów danych, płatnych API ani specjalnego sprzętu. Należy zaprojektować rozwiązanie możliwe do uruchomienia we własnym środowisku, np. z lokalnym modelem, i przygotować własne prompty testowe. Organizatorzy nie zapewniają subskrypcji płatnych usług takich jak OpenAI, Anthropic czy Copilot.

## Kryteria oceny

- Odporność rozwiązania i jakość zabezpieczeń — 30%
- Architektura i wydajność — 20%
- Raportowanie bezpieczeństwa — 20%
- Kompletność zestawu testów własnych — 20% według regulaminu
- Praktyczna możliwość wdrożenia i skalowalność — 10% według regulaminu

**Uwaga:** opis wyzwania podaje dla dwóch ostatnich kryteriów odpowiednio 15% i 15%, natomiast regulamin konkursu podaje 20% i 10%. Łączna waga w obu wersjach wynosi 100%; przed zgłoszeniem warto sprawdzić, która wersja obowiązuje.

## Zgłoszenie

Regulamin przewiduje tytuł projektu, nazwę i skład zespołu, opis oraz prezentację PDF do 10 slajdów. Można dołączyć zrzuty ekranu, repozytorium kodu, demo i inne materiały. Udział indywidualny lub zespołowy, do 6 osób.
