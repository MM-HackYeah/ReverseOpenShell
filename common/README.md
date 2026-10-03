# Wspólny rdzeń MVP

## Cel

Współdzielona warstwa egzekwowania polityk i ograniczania skutków niebezpiecznego wejścia. Ten rdzeń obsługuje dwa scenariusze: ochronę handlera webhooków (Defence) oraz kontrolę wywołań narzędzi przez agenta AI (Goldman Sachs).

## Zakres demonstracyjny

```text
Klient → Gateway → Policy Engine → Isolated Runner → Wynik
                            └────→ Audit Log / Metrics
```

MVP powinno zawierać:

1. Gateway HTTP przyjmujący żądania i przypisujący im identyfikator korelacyjny.
2. Policy Engine czytający konfigurację YAML i zwracający decyzję `allow`, `deny` lub `redact`.
3. Isolated Runner uruchamiający wybrany handler z ograniczonymi uprawnieniami.
4. Audit Log zapisujący decyzję, jej przyczynę, nazwę reguły, czas i wynik wykonania.
5. Prosty interfejs lub endpointy do przeglądania zdarzeń i metryk.
6. Testy automatyczne dla dozwolonych i blokowanych przypadków.

## Minimalny model polityki

```yaml
version: 1
default_action: deny
limits:
  request_bytes: 65536
  execution_seconds: 3
  memory_mb: 128
network:
  default: deny
  allow:
    - api.example.test
rules:
  - id: allow-demo-handler
    action: allow
    target: demo-handler
  - id: redact-demo-secret
    action: redact
    match: "DEMO_SECRET"
```

To przykładowa konfiguracja do demonstracji, nie gotowy format produkcyjny. Zachowanie `default_action` i pierwszeństwo reguł powinny być jednoznaczne i testowane.

## Granice MVP

- Jeden gateway i jeden demonstracyjny handler/agent.
- Jawnie określona lista funkcji; bez obietnicy pełnej ochrony przed exploitami.
- Brak założenia, że kontrola semantyczna AI jest niezawodna. Decyzje bezpieczeństwa w demie powinny dać się odtworzyć testami.
- Bez rozbudowanego systemu multi-tenant, zarządzania kluczami produkcyjnymi i wysokiej dostępności.

## Warunki ukończenia

- Można uruchomić całość jedną udokumentowaną komendą lub zestawem poleceń.
- Zmiana polityki wpływa na kolejne żądania bez przebudowy komponentów.
- Niedozwolone żądanie nie dociera do handlera.
- Runner nie ma dostępu do hostowych sekretów ani niezatwierdzonej sieci.
- Każda decyzja ma wpis audytowy z powodem.
- Testy pokrywają co najmniej po jednym przypadku `allow`, `deny` i `redact`.

## Demonstracja

Pokaż najpierw dozwolone żądanie, następnie żądanie naruszające politykę, a na końcu wpisy audytowe i metryki. Nie prezentuj mockowanych zdarzeń jako wyniku rzeczywistego egzekwowania.
