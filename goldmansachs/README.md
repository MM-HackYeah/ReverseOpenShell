# Goldman Sachs AI Control Layer — MVP

## Problem i użytkownik

Agent AI może zostać nakłoniony do użycia niebezpiecznego narzędzia, ujawnienia danych albo przekroczenia budżetu. Użytkownikami są zespoły developerskie integrujące agentów, a także zespoły bezpieczeństwa monitorujące ich działanie.

## Zakres MVP

- Jeden demonstracyjny agent korzystający z lokalnego modelu lub deterministycznego mocka.
- Proxy przechwytujące każde wywołanie narzędzia i odpowiedź.
- Centralna konfiguracja YAML z listą dozwolonych narzędzi, regułami blokowania/redakcji oraz limitami wywołań i budżetu.
- Deterministyczne kontrole: walidacja schematu, allowlista narzędzi i endpointów, wykrywanie przykładowego sekretu.
- Jeden izolowany runner dla ryzykownej akcji, np. przetworzenia pliku w przygotowanym katalogu.
- Audyt i prosty dashboard: dozwolone, zablokowane i zredagowane interakcje, przyczyny decyzji oraz użycie limitów.
- Automatyczny zestaw testów pozytywnych i negatywnych.
- Przeładowanie polityki w czasie działania.

Kontrolę semantyczną można dodać jako opcjonalny element, ale nie powinna być jedyną barierą bezpieczeństwa. Bezpłatny lokalny model lub mock pozwala uniknąć zależności od płatnego API.

## Scenariusz demonstracyjny

1. Agent wykonuje dozwolone narzędzie, np. wyszukuje informację w katalogu demonstracyjnym.
2. Złośliwa instrukcja w danych wejściowych próbuje skłonić agenta do odczytania sekretu albo wysłania danych do niedozwolonego hosta.
3. Policy Engine odrzuca niedozwolone narzędzie lub redaguje sekret; runner ogranicza dostęp procesu do plików i sieci.
4. Dashboard pokazuje decyzję, regułę, zdarzenie audytowe i stan limitu budżetowego.
5. Zmień konfigurację, np. zablokuj wcześniej dozwolone narzędzie, i pokaż efekt na kolejnym żądaniu.

## Minimalny zestaw testów

- Dozwolone narzędzie i poprawne wejście → wykonanie.
- Nieznane narzędzie → blokada.
- Sekret w danych → redakcja lub blokada zgodnie z polityką.
- Przekroczony limit wywołań/budżetu → blokada.
- Próba dostępu runnera do niedozwolonego pliku lub hosta → brak dostępu i wpis audytowy.
- Zmiana konfiguracji → nowa decyzja bez restartu, jeśli taki tryb jest zaimplementowany.

## Kryteria ukończenia

- Działa pełny przepływ od promptu do kontrolowanego wywołania narzędzia.
- Polityki są centralne, widoczne i możliwe do zmiany.
- Testy zawierają przypadki pozytywne i negatywne.
- Dashboard/logi prezentują decyzję i jej uzasadnienie.
- Limity budżetu lub zasobów są faktycznie egzekwowane, a nie tylko wyświetlane.
- Całość można uruchomić bez płatnych usług.

## Poza zakresem

Pełna zgodność z każdym frameworkiem agentowym, ochrona przed wszystkimi prompt injection, produkcyjna usługa multi-tenant, automatyczne pozyskiwanie sygnatur z wielu źródeł i rozbudowany system zarządzania kluczami.

## Prezentacja

Pokaż działający dozwolony przepływ, próbę niebezpiecznego wywołania, blokadę lub redakcję, wpis audytowy, wykorzystanie budżetu oraz zmianę zachowania po edycji polityki. Przygotuj testy do uruchomienia przez oceniających i wskaż ograniczenia prototypu.
