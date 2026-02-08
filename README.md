# KSeF Faktury List

Samodzielny skrypt Python do pobierania faktur z KSeF (Krajowy System e-Faktur).

## Opis

Skrypt umożliwia:
- Autoryzację w systemie KSeF przy użyciu:
  - Certyfikatu kwalifikowanego (XAdES-BES)
  - Tokenu autoryzacyjnego KSeF
- Pobieranie listy faktur zakupowych (otrzymanych) lub sprzedażowych (wystawionych)
- Eksport wyników w formacie tabeli lub JSON
- Pobieranie pełnych plików XML faktur
- Generowanie faktur w formacie PDF z pełną obsługą polskich znaków
- Wysyłanie faktur e-mailem (PDF + XML jako załączniki) przez SMTP

## Wymagania

- Python 3.8+
- Jedna z metod autoryzacji:
  - **Certyfikat**: Certyfikat kwalifikowany zarejestrowany w KSeF (plik `.pem`) + klucz prywatny
  - **Token**: Token autoryzacyjny wygenerowany w portalu KSeF

## Instalacja

```bash
# Klonowanie repozytorium
git clone https://github.com/your-username/ksef-faktury-list.git
cd ksef-faktury-list

# Instalacja zależności
pip install -r requirements.txt
```

### Zależności

```
requests>=2.28.0
lxml>=4.9.0
cryptography>=38.0.0
reportlab>=4.0.0
```

### Fonty (dla generowania PDF)

Do poprawnego wyświetlania polskich znaków w PDF wymagany jest font **DejaVu Sans**.

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install fonts-dejavu-core
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install dejavu-sans-fonts
```

**Windows:**
Font DejaVu Sans można pobrać z [dejavu-fonts.github.io](https://dejavu-fonts.github.io/) i zainstalować w systemie.

Jeśli font nie zostanie znaleziony, PDF będzie generowany z domyślnym fontem Helvetica (bez polskich znaków).

## Docker

### Budowanie obrazu

```bash
docker build -t ksef-faktury .
```

### Uruchomienie

**Wyświetl pomoc:**
```bash
docker run --rm ksef-faktury
```

**Pobierz faktury zakupowe:**
```bash
docker run --rm \
  -v /ścieżka/do/certyfikatów:/certs:ro \
  -v /ścieżka/do/wyników:/output \
  ksef-faktury \
  --nip 1234567890 \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --password "haslo" \
  --env prod
```

**Pobierz faktury wraz z plikami XML:**
```bash
docker run --rm \
  -v /ścieżka/do/certyfikatów:/certs:ro \
  -v /ścieżka/do/wyników:/output \
  ksef-faktury \
  --nip 1234567890 \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --password-file /certs/haslo.txt \
  --download-xml \
  --xml-output-dir /output
```

**Generuj faktury jako PDF:**
```bash
docker run --rm \
  -v /ścieżka/do/certyfikatów:/certs:ro \
  -v /ścieżka/do/wyników:/output \
  ksef-faktury \
  --nip 1234567890 \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --password-file /certs/haslo.txt \
  --download-pdf \
  --pdf-output-dir /output
```

**Użycie zmiennej środowiskowej dla hasła:**
```bash
docker run --rm \
  -v /ścieżka/do/certyfikatów:/certs:ro \
  -e KSEF_PASSWORD="haslo" \
  ksef-faktury \
  --nip 1234567890 \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --password "$KSEF_PASSWORD"
```

**Autoryzacja tokenem w Docker:**
```bash
docker run --rm \
  -v /ścieżka/do/tokenu:/certs:ro \
  -v /ścieżka/do/wyników:/output \
  ksef-faktury \
  --nip 1234567890 \
  --token-file /certs/token.txt \
  --download-pdf \
  --pdf-output-dir /output
```

**Konwersja XML na PDF offline (bez autoryzacji):**
```bash
docker run --rm \
  -v /ścieżka/do/xml:/input:ro \
  -v /ścieżka/do/wyników:/output \
  ksef-faktury \
  --xml-to-pdf /input \
  --pdf-output-dir /output
```

**Pobierz faktury i wyślij e-mailem:**
```bash
docker run --rm \
  -v /ścieżka/do/certyfikatów:/certs:ro \
  ksef-faktury \
  --nip 1234567890 \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --password-file /certs/haslo.txt \
  --smtp-host smtp.gmail.com \
  --smtp-user user@gmail.com \
  --smtp-password "haslo-aplikacji" \
  --email-to odbiorca@example.com
```

### Wolumeny

| Ścieżka w kontenerze | Opis |
|----------------------|------|
| `/certs` | Katalog na certyfikat, klucz prywatny lub token (montuj jako read-only `:ro`) |
| `/output` | Katalog na pobrane pliki XML i PDF faktur |

### Docker Compose

Przykładowy `docker-compose.yml` (certyfikat):

```yaml
services:
  ksef:
    build: .
    volumes:
      - ./certs:/certs:ro
      - ./output:/output
    command:
      - --nip
      - "1234567890"
      - --cert
      - /certs/cert.pem
      - --key
      - /certs/key.pem
      - --password-file
      - /certs/haslo.txt
      - --download-xml
      - --xml-output-dir
      - /output
      - --download-pdf
      - --pdf-output-dir
      - /output
```

Przykładowy `docker-compose.yml` (token):

```yaml
services:
  ksef:
    build: .
    volumes:
      - ./certs:/certs:ro
      - ./output:/output
    command:
      - --nip
      - "1234567890"
      - --token-file
      - /certs/token.txt
      - --download-pdf
      - --pdf-output-dir
      - /output
```

Uruchomienie:
```bash
docker compose run --rm ksef
```

## Użycie

### Podstawowe użycie

**Autoryzacja certyfikatem (XAdES):**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert certyfikat.pem --key klucz.pem --password haslo
```

**Autoryzacja tokenem:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt
```

### Opcje

| Opcja | Opis |
|-------|------|
| `--nip` | NIP podmiotu (wymagane dla zapytań do KSeF) |
| **Konwersja offline** | |
| `--xml-to-pdf` | Konwertuj plik XML lub katalog plików XML na PDF (bez autoryzacji KSeF) |
| **Autoryzacja certyfikatem** | |
| `--cert` | Ścieżka do pliku certyfikatu (PEM) |
| `--key` | Ścieżka do pliku klucza prywatnego (PEM) |
| `--password` | Hasło do klucza prywatnego |
| `--password-file` | Plik zawierający hasło do klucza |
| **Autoryzacja tokenem** | |
| `--token` | Token autoryzacyjny KSeF |
| `--token-file` | Plik zawierający token KSeF |
| **Pozostałe opcje** | |
| `--env` | Środowisko: `test`, `demo`, `prod` (domyślnie: `prod`) |
| `--date-from` | Data początkowa YYYY-MM-DD (domyślnie: 30 dni wstecz) |
| `--date-to` | Data końcowa YYYY-MM-DD (domyślnie: dziś) |
| `--subject-type` | `Subject1` (sprzedaż) lub `Subject2` (zakup, domyślnie) |
| `--output` | Format wyjścia: `table`, `json` (domyślnie: `table`) |
| `--download-xml` | Pobierz pełne pliki XML faktur |
| `--xml-output-dir` | Katalog do zapisu plików XML (domyślnie: bieżący) |
| `--download-pdf` | Generuj pliki PDF dla każdej faktury |
| `--pdf-output-dir` | Katalog do zapisu plików PDF (domyślnie: bieżący) |
| `--verbose`, `-v` | Włącz szczegółowe logowanie |
| **Wysyłanie e-mail** | |
| `--send-email` | Włącz wysyłanie faktur e-mailem (włączane automatycznie gdy podano `--smtp-host`) |
| `--smtp-host` | Adres serwera SMTP |
| `--smtp-port` | Port SMTP (domyślnie: `587`) |
| `--smtp-user` | Użytkownik SMTP |
| `--smtp-password` | Hasło SMTP |
| `--smtp-password-file` | Plik zawierający hasło SMTP |
| `--email-from` | Adres nadawcy (domyślnie: wartość `--smtp-user`) |
| `--email-to` | Adres odbiorcy (można podać wielokrotnie) |
| `--email-subject` | Szablon tematu e-maila (domyślnie: `"Faktura KSeF: {invoice_number}"`) |
| `--email-group` | Grupowanie: `single` (osobny mail per faktura, domyślnie) lub `all` (wszystkie w jednym mailu) |

### Przykłady

**Pobierz faktury zakupowe z ostatnich 30 dni:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo
```

**Pobierz faktury sprzedażowe za styczeń 2025:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --subject-type Subject1 --date-from 2025-01-01 --date-to 2025-01-31
```

**Eksport do JSON:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --output json > faktury.json
```

**Pobierz faktury wraz z plikami XML:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --download-xml --xml-output-dir ./faktury_xml
```

**Generuj faktury jako PDF:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --download-pdf --pdf-output-dir ./faktury_pdf
```

**Pobierz XML i wygeneruj PDF jednocześnie:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --download-xml --xml-output-dir ./xml \
    --download-pdf --pdf-output-dir ./pdf
```

**Pobierz faktury używając tokenu:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt
```

**Token z plikami PDF:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --download-pdf --pdf-output-dir ./faktury_pdf
```

**Użycie hasła z pliku (bezpieczniejsze):**
```bash
echo "moje_haslo" > haslo.txt
chmod 600 haslo.txt
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password-file haslo.txt
```

**Użycie środowiska testowego:**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo --env test
```

**Konwersja istniejącego pliku XML na PDF (offline, bez autoryzacji):**
```bash
python ksef_faktury_list.py --xml-to-pdf faktura.xml
```

**Konwersja całego katalogu plików XML na PDF:**
```bash
python ksef_faktury_list.py --xml-to-pdf ./faktury_xml/ --pdf-output-dir ./faktury_pdf/
```

### Wysyłanie faktur e-mailem

**Wyślij faktury na e-mail (osobny mail per faktura):**
```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo \
    --smtp-host smtp.gmail.com \
    --smtp-user user@gmail.com \
    --smtp-password "haslo-aplikacji" \
    --email-to odbiorca@example.com
```

**Wyślij na wiele adresów:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --smtp-host smtp.gmail.com \
    --smtp-user user@gmail.com \
    --smtp-password "haslo-aplikacji" \
    --email-to odbiorca1@example.com \
    --email-to odbiorca2@example.com
```

**Wszystkie faktury w jednym mailu:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --smtp-host smtp.gmail.com \
    --smtp-user user@gmail.com \
    --smtp-password "haslo-aplikacji" \
    --email-to odbiorca@example.com \
    --email-group all
```

**Niestandardowy adres nadawcy i temat:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --smtp-host smtp.firma.pl \
    --smtp-user ksef@firma.pl \
    --smtp-password-file smtp_haslo.txt \
    --email-from "Księgowość <ksiegowosc@firma.pl>" \
    --email-to kontrahent@example.com \
    --email-subject "Faktura nr {invoice_number} - Firma Sp. z o.o."
```

**Hasło SMTP z pliku (bezpieczniejsze):**
```bash
echo -n "haslo-smtp" > smtp_haslo.txt
chmod 600 smtp_haslo.txt
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --smtp-host smtp.gmail.com \
    --smtp-user user@gmail.com \
    --smtp-password-file smtp_haslo.txt \
    --email-to odbiorca@example.com
```

**Pobierz PDF + XML i wyślij mailem jednocześnie:**
```bash
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt \
    --download-xml --xml-output-dir ./xml \
    --download-pdf --pdf-output-dir ./pdf \
    --smtp-host smtp.gmail.com \
    --smtp-user user@gmail.com \
    --smtp-password "haslo-aplikacji" \
    --email-to odbiorca@example.com
```

> **Uwaga:** Gdy używasz jednocześnie `--download-xml`, `--download-pdf` i wysyłki e-mail, skrypt pobiera XML z KSeF tylko raz (cache) — nie ma duplikowania zapytań API.

## Metody autoryzacji

### Autoryzacja certyfikatem (XAdES-BES)

Wymaga certyfikatu kwalifikowanego zarejestrowanego w portalu KSeF. Certyfikat musi być w formacie PEM.

```bash
python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password haslo
```

### Autoryzacja tokenem

Token autoryzacyjny można wygenerować w portalu KSeF ([ksef.mf.gov.pl](https://ksef.mf.gov.pl)) w sekcji "Tokeny". Token jest szyfrowany kluczem publicznym KSeF (RSA-OAEP z SHA-256).

**Generowanie tokenu w portalu KSeF:**
1. Zaloguj się do portalu KSeF
2. Przejdź do sekcji "Tokeny" → "Generuj token"
3. Nadaj nazwę tokenowi i wybierz uprawnienia (np. odczyt faktur)
4. Skopiuj wygenerowany token (wyświetlany tylko raz!)
5. Zapisz token do pliku: `echo "twoj-token" > token.txt`

**Użycie tokenu:**
```bash
# Token bezpośrednio w linii poleceń
python ksef_faktury_list.py --nip 1234567890 --token "twoj-token-ksef"

# Token z pliku (zalecane)
python ksef_faktury_list.py --nip 1234567890 --token-file token.txt
```

**Zalety autoryzacji tokenem:**
- Nie wymaga certyfikatu kwalifikowanego
- Można ograniczyć uprawnienia tokenu (np. tylko odczyt)
- Token można w każdej chwili unieważnić w portalu KSeF
- Prostsze wdrożenie w środowiskach automatyzacji

## Środowiska KSeF

| Środowisko | URL | Opis |
|------------|-----|------|
| `test` | api-test.ksef.mf.gov.pl | Środowisko testowe |
| `demo` | api-demo.ksef.mf.gov.pl | Środowisko demonstracyjne |
| `prod` | api.ksef.mf.gov.pl | Środowisko produkcyjne |

## Generowanie PDF

Opcja `--download-pdf` generuje pliki PDF z faktur pobranych z KSeF. Każdy PDF zawiera:

- **Nagłówek** - numer faktury VAT, data wystawienia, okres rozliczeniowy (jeśli dotyczy)
- **Dane sprzedawcy** - nazwa, NIP, adres
- **Dane nabywcy** - nazwa, NIP, adres
- **Tabela pozycji** - lp., nazwa towaru/usługi, jednostka miary, ilość, cena netto, wartość netto, stawka VAT
- **Podsumowanie** - wartość netto, VAT, kwota brutto do zapłaty
- **Stopka** - informacje dodatkowe, dane rejestrowe (KRS, REGON)

### Obsługiwane waluty

PDF obsługuje faktury w różnych walutach (PLN, EUR, USD itp.). Dla faktur w walutach obcych wyświetlana jest również przeliczona wartość VAT w PLN (jeśli dostępna w XML).

### Nazwa pliku

Pliki PDF są zapisywane z nazwą odpowiadającą numerowi KSeF faktury, np.:
```
1234567890-20250115-ABC123DEF456-01.pdf
```

## Przykładowy wynik

```
Łączenie z KSeF (środowisko: prod)...
NIP: 1234567890
Metoda autoryzacji: certyfikat (XAdES)
Sesja zainicjalizowana. Numer referencyjny: 20250205-SE-ABC123DEF456

Pobieranie faktur otrzymane (zakupy)...

========================================================================================================================
Numer KSeF                                    Nr faktury           Data         NIP sprzed.  Kwota brutto
========================================================================================================================
1234567890-20250115-ABC123DEF456-01          FV/2025/001          2025-01-15   9876543210         1,230.00
1234567890-20250120-ABC123DEF456-02          FV/2025/002          2025-01-20   9876543210         2,460.00
========================================================================================================================
Razem: 2 faktur(a/y)

Kończenie sesji...
Sesja zakończona.
```

## Wysyłanie e-mail

### Opis

Opcje `--smtp-*` i `--email-*` umożliwiają wysyłanie pobranych faktur e-mailem. Każda faktura jest wysyłana z dwoma załącznikami:
- **PDF** — wizualna reprezentacja faktury
- **XML** — oryginalna faktura KSeF

Wysyłka jest włączana automatycznie po podaniu `--smtp-host`. Adres nadawcy (`--email-from`) domyślnie przyjmuje wartość `--smtp-user`.

### Tryby grupowania

| Tryb | Opis |
|------|------|
| `single` (domyślnie) | Osobny e-mail dla każdej faktury |
| `all` | Wszystkie faktury w jednym e-mailu ze wszystkimi załącznikami |

### Szablon tematu

Opcja `--email-subject` przyjmuje szablon z placeholderem `{invoice_number}`:
- W trybie `single`: zastępowany numerem faktury, np. `FV/2025/001`
- W trybie `all`: zastępowany liczbą faktur, np. `3 faktur`

### Konfiguracja Gmail

Gmail wymaga użycia **Hasła do aplikacji** (App Password) zamiast zwykłego hasła:

1. Włącz weryfikację dwuetapową na koncie Google
2. Wygeneruj hasło aplikacji: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Użyj wygenerowanego 16-znakowego hasła jako `--smtp-password`

| Parametr | Wartość dla Gmail |
|----------|-------------------|
| `--smtp-host` | `smtp.gmail.com` |
| `--smtp-port` | `587` (domyślnie) |
| `--smtp-user` | twój adres Gmail |
| `--smtp-password` | 16-znakowe hasło aplikacji |

### Cache XML/PDF

Gdy używasz jednocześnie `--download-xml`, `--download-pdf` i wysyłki e-mail, skrypt wykorzystuje wewnętrzny cache — XML każdej faktury jest pobierany z KSeF tylko raz, niezależnie od liczby operacji które go wymagają.

## Uwagi

- Maksymalny zakres dat to 90 dni (ograniczenie API KSeF)
- Maksymalna liczba wyników na stronę to 250
- Certyfikat musi być zarejestrowany w KSeF i mieć przypisane uprawnienia do podmiotu (NIP)
- Generowanie PDF wymaga pobrania pełnego XML faktury z KSeF (dodatkowe zapytania API)
- PDF jest generowany na podstawie schematu FA (3) - głównego formatu faktur KSeF

## Rozwiązywanie problemów

### Błąd: "Brak przypisanych uprawnień" (kod 415)

- Sprawdź czy certyfikat jest zarejestrowany w KSeF dla podanego NIP
- Sprawdź czy używasz właściwego środowiska (`test`, `demo`, `prod`)
- Upewnij się, że certyfikat ma przypisane uprawnienia w panelu KSeF

### Błąd: "Error loading private key"

- Sprawdź czy hasło do klucza jest poprawne
- Sprawdź czy plik klucza jest w formacie PEM

### Błąd połączenia

- Sprawdź połączenie internetowe
- Sprawdź czy adresy API KSeF nie są blokowane przez firewall

### Brak polskich znaków w PDF

- Zainstaluj font DejaVu Sans (patrz sekcja "Fonty")
- W Dockerze font jest instalowany automatycznie
- Sprawdź czy font jest dostępny w jednej z lokalizacji:
  - `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf` (Debian/Ubuntu)
  - `/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf` (Fedora/RHEL)

### Błąd generowania PDF

- Upewnij się, że masz zainstalowany pakiet `reportlab`: `pip install reportlab`
- Sprawdź czy katalog wyjściowy istnieje i masz uprawnienia do zapisu

## Licencja

MIT License - szczegóły w pliku [LICENSE](LICENSE) lub w nagłówku skryptu.

## Linki

- [Dokumentacja KSeF](https://www.podatki.gov.pl/ksef/)
- [API KSeF - GitHub](https://github.com/CIRFMF/ksef-docs)
