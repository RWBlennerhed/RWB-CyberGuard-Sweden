# RWB CyberGuard Sweden 3.0 Alpha 6

## Webbadresshantering – Chromebook/Linux

RWB CyberGuard Sweden är ett lokalt Pythonprogram för manuella, passiva säkerhetskontroller av webbplatser och analys av säkerhetsrelaterad information.

### Systemkrav

- Chromebook med aktiverad Linuxmiljö (Crostini), eller kompatibel Linuxdistribution.
- Python 3.
- Tkinter för det grafiska gränssnittet.
- Internetanslutning för kontroller som hämtar extern information.
På Debianbaserad Linux kan Tkinter installeras med:

```bash
sudo apt install python3-tk
```
### Installation

1. Packa upp ZIP-filen i Linux-filer.
2. Öppna terminalen i den uppackade katalogen Alpha6.
3. Kör bash install.sh.
4. Starta programmet från programmenyn.
Alpha 6 installeras separat från Alpha 5.

### Funktioner

- Registrera, redigera, välja och ta bort webbplatser.
- Manuell passiv webbplatskontroll.
- TLS- och HTTP-säkerhetsinformation.
- PHP Security Inspector och PHP Session Configuration Advisor.
- Analys av lokala loggfiler.
- CISA KEV-information.
- Security Advisor.
- Lokal historik och rapportexport.
### Webbadresshantering

- En ny installation har inga förregistrerade webbplatser.
- Webbadresslistan sparas lokalt i ~/RWB-CyberGuard/Webbadresser/webbadresser.json.
- Kontrollnivå 1 innebär manuella, passiva kontroller.
- "Bevakning aktiv" är en inställning för eventuella framtida funktioner och startar ingen automatisk kontroll.
### PHP Security Inspector

PHP-versionen anges manuellt av användaren. Ingen PHP-analys körs automatiskt när programmet startar.

### Säkerhet och begränsningar

Programmet utför inte automatiska schemalagda säkerhetskontroller och garanterar inte att en undersökt webbplats är säker.

Användaren måste bekräfta tillstånd innan en webbplatskontroll genomförs.

Historik sparas lokalt och delas för närvarande med Alpha 5. Befintliga data påverkas inte av själva installationen.

### Ikon och programstart

Den medföljande ikonen installeras automatiskt. Alpha 6 använder ett separat programnamn och Tkinter-klassnamn för ChromeOS/Linux.

### Ominstallation

Vid ominstallation säkerhetskopieras den tidigare installerade Alpha 6-koden i:

`~/RWB-CyberGuard/Sakerhetskopior/Installationer/`
Befintliga webbplatser och historik bevaras vid installationen.

### Utvecklare

RWB Tech Lab

[RWB Tech Lab](https://www.rwb-tech-lab.com)
Version: 3.0 Alpha 6
