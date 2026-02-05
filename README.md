# KSeF Faktury List

Samodzielny skrypt Python do pobierania faktur z KSeF (Krajowy System e-Faktur).

## Opis

Skrypt umożliwia:
- Autoryzację w systemie KSeF przy użyciu certyfikatu kwalifikowanego (XAdES-BES)
- Pobieranie listy faktur zakupowych (otrzymanych) lub sprzedażowych (wystawionych)
- Eksport wyników w formacie tabeli lub JSON
- Pobieranie pełnych plików XML faktur
- Generowanie faktur w formacie PDF z pełną obsługą polskich znaków

## Wymagania

- Python 3.8+
- Certyfikat kwalifikowany zarejestrowany w KSeF (plik `.crt` lub `.pem`)
- Klucz prywatny do certyfikatu (plik `.key` lub `.pem`)

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

### Wolumeny

| Ścieżka w kontenerze | Opis |
|----------------------|------|
| `/certs` | Katalog na certyfikat i klucz prywatny (montuj jako read-only `:ro`) |
| `/output` | Katalog na pobrane pliki XML i PDF faktur |

### Docker Compose

Przykładowy `docker-compose.yml`:

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

Uruchomienie:
```bash
docker compose run --rm ksef
```

## Użycie

### Podstawowe użycie

```bash
python ksef_faktury_list.py --nip 1234567890 --cert certyfikat.crt --key klucz.key --password haslo
```

### Opcje

| Opcja | Opis |
|-------|------|
| `--nip` | NIP podmiotu (wymagane) |
| `--cert` | Ścieżka do pliku certyfikatu (PEM) |
| `--key` | Ścieżka do pliku klucza prywatnego (PEM) |
| `--password` | Hasło do klucza prywatnego |
| `--password-file` | Plik zawierający hasło do klucza |
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
Connecting to KSeF (prod environment)...
NIP: 1234567890
Session initialized. Reference: 20250205-SE-ABC123DEF456

Querying Subject2 invoices...

========================================================================================================================
KSeF Number                                   Invoice #            Date         Seller NIP   Gross Amount
========================================================================================================================
1234567890-20250115-ABC123DEF456-01          FV/2025/001          2025-01-15   9876543210         1,230.00
1234567890-20250120-ABC123DEF456-02          FV/2025/002          2025-01-20   9876543210         2,460.00
========================================================================================================================
Total: 2 invoice(s)

Terminating session...
Session terminated.
```

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
