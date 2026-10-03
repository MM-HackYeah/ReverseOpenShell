# Scenariusz demonstracyjny: wodociąg

## Założony przepływ

Operator przedsiębiorstwa wodociągowego odbiera raporty telemetryczne od zewnętrznego dostawcy. Adapter dostawcy parsuje dokument YAML, a wynik może zostać wykorzystany przez wewnętrzny proces telemetryczny. Atakujący wysyła poprawnie podpisany `telemetry.read` z dokumentem, który wykorzystuje celowo podatny parser.

Demo używa wyłącznie fikcyjnego źródła `sensor-a`, tekstu `SYNTHETIC-CANARY-NOT-A-REAL-SECRET`, lokalnego kolektora i pliku JSON udającego nastawę przepływu. Nie łączy się z PLC, SCADA, siecią OT ani prawdziwym systemem wodociągowym.

## Odniesienie do IEC 62443

To jest szkic architektury zgodny z pojęciami stref i kanałów komunikacyjnych (zones and conduits), nie ocena zgodności ani projekt docelowy.

| Element demonstracji | Przykładowa rola w podziale na strefy | Znaczenie ograniczenia |
|---|---|---|
| Webhook i weryfikacja HMAC | Strefa DMZ/edge przyjmująca dane zewnętrzne | Uwierzytelnienie źródła nie oznacza zaufania do treści dokumentu |
| Parser vendor YAML w OpenShell | Izolowany workload pośredni, nie strefa sterowania | Ogranicza skutki kompromitacji do procesu i jego jawnie dostępnych zasobów |
| Syntetyczny plik nastawy | Atrapa zasobu w chronionej strefie procesu | Polityka ma zablokować dostęp; w demonstracji nie ma rzeczywistego zasobu OT |
| Lokalny kolektor | Atrapa niedozwolonego kanału wychodzącego | Egress ma zostać odrzucony; sprawdź zdarzenie polityki OpenShell |
| Osobny sandbox per źródło | Granica izolacji pomiędzy workloadami | Incydent źródła A nie powinien przerwać obsługi źródła B |

IEC 62443-3-2 opisuje definiowanie systemu będącego przedmiotem oceny, jego podział na strefy i kanały oraz ocenę ryzyka. Sam sandbox ani ta tabela nie ustanawiają stref OT, Security Level, ani zgodności z serią IEC 62443. W rzeczywistym wdrożeniu operator musiałby zidentyfikować aktywa, zależności, kanały oraz wymagania bezpieczeństwa dla konkretnego systemu.

## Odniesienie do MITRE ATT&CK for ICS

- **T0836, Modify Parameter:** demonstracyjny payload próbuje zmienić wartość w pliku JSON udającym nastawę. To odpowiada próbie modyfikacji parametru na poziomie koncepcji, ale nie zmienia parametru urządzenia przemysłowego.
- **T0831, Manipulation of Control:** byłoby istotne dopiero, gdyby dostęp do sterowania pozwalał wpłynąć na proces fizyczny. Demo nie wykonuje takiego działania i nie dowodzi ochrony przed manipulacją procesu.
- Scenariusz dodatkowo pokazuje ryzyko wykonania kodu przez parser niezaufanego wejścia; nie przypisuje temu konkretnej techniki ICS bez dowodu, że technika ta pasuje do rzeczywistej ścieżki ataku.

## Odniesienie do NIS2, Article 21

Demo ilustruje ograniczony zestaw tematów z Article 21 risk-management measures: obsługę incydentu, bezpieczeństwo łańcucha dostaw, kontrolę dostępu i ciągłość działania. Podpis HMAC identyfikuje źródło, allowlista ingress ogranicza dozwoloną akcję, sandbox ogranicza skutki błędu parsera, a kwarantanna jednego źródła ma pozostawić drugie aktywne.

To nie jest ocena ryzyka organizacji, wdrożenie wszystkich wymaganych środków, certyfikacja ani opinia prawna. Zakres obowiązków zależy od podmiotu, sektora, krajowej implementacji dyrektywy i kontekstu operacyjnego. Lokalny token operatora i plik SQLite są tylko demonstracyjnymi mechanizmami, a nie odpowiednikiem zarządzania tożsamością, wysokiej dostępności czy procesu reagowania organizacji.

## Źródła

- [IEC 62443-3-2:2020, official IEC catalogue](https://webstore.iec.ch/en/publication/30727)
- [MITRE ATT&CK for ICS: T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/)
- [MITRE ATT&CK for ICS: T0831 Manipulation of Control](https://attack.mitre.org/techniques/T0831/)
- [Directive (EU) 2022/2555 (NIS2), EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)
