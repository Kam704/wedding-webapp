# Wedding RSVP Webapp

Nowoczesne zaproszenie ślubne oparte na Flasku z panelem RSVP, konfiguracją lokalizacji i zabezpieczonym kokpitem administratora.

## Wymagania

- Python 3.12+
- Wirtualne środowisko (`python -m venv venv`)

## Instalacja

```bash
cd wedding-webapp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Konfiguracja

W pliku `.env` ustaw:

```
SECRET_KEY=twoj_super_tajny_klucz
INVITE_PASSWORD=haslo_dla_gosci
INVITE_PASSWORD_HASH=opcjonalny_hash_bcrypt
ADMIN_PASSWORD=haslo_admina
ADMIN_PASSWORD_HASH=opcjonalny_hash_bcrypt
DATABASE=rsvp.db
SESSION_COOKIE_SECURE=false
SESSION_LIFETIME_MINUTES=120
ADMIN_IP_ALLOWLIST=127.0.0.1,192.168.0.0/24,10.0.*
```

> Jeśli podasz `*_PASSWORD_HASH`, wartości w `INVITE_PASSWORD` i `ADMIN_PASSWORD` służą jedynie jako fallback.
> Lista `ADMIN_IP_ALLOWLIST` jest opcjonalna – pojedyncze adresy oddziel przecinkami. Gdy pole pozostanie puste, dostęp mają wszystkie adresy lub wartości ustawione z poziomu panelu.

## Uruchomienie

```bash
source venv/bin/activate
python app.py
```

Domyślnie aplikacja startuje na `http://127.0.0.1:10500`.

## Funkcje

- Strona wejściowa chroniona hasłem
- Formularz RSVP (gość, dieta, dzieci) z walidacją oraz imienną osobą towarzyszącą
- Panel administratora z podsumowaniami, edycją lokalizacji, zaproszeniami i eksportem CSV
- Usuwanie zgłoszeń i konfiguracja linków do map Google
- Zabezpieczenia: sesje HTTPOnly, CSRF, opcjonalny bcrypt dla haseł i ACL IP dla panelu

## ACL panelu admina

- W panelu znajdziesz kartę „Lista dozwolonych adresów IP” – jedno IP na linię, obsługiwane są CIDR (np. `192.168.0.0/24`) i wildcard (`10.0.*`).
- Puste pole oznacza dopuszczenie wszystkich adresów (lub wartości z `ADMIN_IP_ALLOWLIST`).
- Gdy IP nie spełnia listy, przycisk „Admin” znika, logowanie jest blokowane, a dostęp do `/admin/panel` kończy się błędem 403.
