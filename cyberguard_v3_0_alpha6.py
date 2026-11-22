"""RWB CyberGuard Sweden 3.0 Alpha 6 – defensiv webbplatskontroll.
Endast webbplatser du äger eller har tillstånd att kontrollera.
Standardbibliotek: Python 3.11+.
"""
import datetime as dt
import csv
import io
import re
from xml.sax.saxutils import escape as xml_escape
from zipfile import ZipFile, ZIP_DEFLATED
import json
from pathlib import Path
import ipaddress
import queue
import socket
import ssl
import threading
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

VERSION = "3.0 Alpha 6"
TIMEOUT = 8
MAX_PAGES = 5
MAX_REDIRECTS = 4
HISTORY_PATH = Path.home() / ".local" / "share" / "RWB-CyberGuard" / "history.json"
MAX_HISTORY = None  # Bevara all tidigare historik.
USER_AGENT = "RWB-CyberGuard/3.0-Alpha6 (owner-authorized passive check)"


def normalize_url(value, allow_legacy=False):
    value = value.strip()
    if not allow_legacy and any(char.isspace() for char in value):
        raise ValueError("Webbadressen får inte innehålla blanksteg.")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Ange en fullständig adress med https://")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Ange en HTTPS-adress utan inloggning eller fragment (#).")
    if parsed.port not in (None, 443):
        raise ValueError("Endast standardporten 443 stöds.")
    if parsed.hostname.endswith("."):
        raise ValueError("Ange domännamn utan avslutande punkt.")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Ange ett domännamn, inte en IP-adress.")
    return parsed.geturl()


def same_host(url, original_host):
    parts = urlsplit(url)
    return (parts.scheme.lower() == "https" and
            parts.hostname == original_host and
            parts.port in (None, 443) and
            not parts.username and not parts.password)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = build_opener(NoRedirect)


def get_page(url, original_host):
    """Hämta headers från max ett fåtal HTTPS-omdirigeringar inom samma domän."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        if not same_host(current, original_host):
            raise ValueError("Omdirigering utanför vald HTTPS-domän blockerades.")
        req = Request(current, headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            response = OPENER.open(req, timeout=TIMEOUT)
        except HTTPError as error:
            response = error
        with response:
            status = response.status
            headers = response.headers
            location = headers.get("Location")
            # Ingen sidtext läses; endast svarshuvuden kontrolleras.
        if status in (301, 302, 303, 307, 308) and location:
            candidate = urljoin(current, location)
            if not same_host(candidate, original_host):
                raise ValueError("Extern eller okrypterad omdirigering blockerades.")
            current = candidate
            continue
        return current, status, headers
    raise ValueError("För många omdirigeringar.")


def inspect_headers(headers):
    findings = []
    def add(symbol, message):
        findings.append(f"{symbol} {message}")

    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        add("✓", f"HSTS finns: {hsts[:150]}")
    else:
        add("!", "HSTS saknas på detta svar.")

    csp = headers.get("Content-Security-Policy", "")
    csp_report = headers.get("Content-Security-Policy-Report-Only", "")
    if csp:
        add("✓", "Content-Security-Policy finns (reglernas kvalitet ej granskad).")
    elif csp_report:
        add("!", "CSP finns bara i Report-Only-läge, inte som tvingande skydd.")
    else:
        add("!", "Content-Security-Policy saknas på detta svar.")

    xcto = headers.get("X-Content-Type-Options", "")
    if xcto.lower().strip() == "nosniff":
        add("✓", "X-Content-Type-Options: nosniff")
    else:
        add("!", "X-Content-Type-Options saknas eller är inte 'nosniff'.")

    referrer = headers.get("Referrer-Policy", "")
    if referrer:
        add("✓", f"Referrer-Policy finns: {referrer[:100]}")
    else:
        add("!", "Referrer-Policy saknas (webbläsarens standard gäller).")

    xfo = headers.get("X-Frame-Options", "")
    frame_ancestors = "frame-ancestors" in csp.lower()
    if frame_ancestors:
        add("✓", "CSP frame-ancestors finns (inbäddningsskydd).")
    elif xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        add("✓", f"X-Frame-Options: {xfo[:70]}")
    else:
        add("!", "Inget identifierat inbäddningsskydd (X-Frame-Options / CSP frame-ancestors).")
    return findings


def tls_info(host):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    expiry_raw = cert.get("notAfter")
    if not expiry_raw:
        return [f"✓ Giltig TLS-anslutning: {version}", "! Utgångsdatum kunde inte läsas."]
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_raw), dt.timezone.utc)
    remaining = expires - dt.datetime.now(dt.timezone.utc)
    days = int(remaining.total_seconds() // 86400)
    symbol = "!" if days < 30 else "✓"
    return [f"✓ Giltig TLS-anslutning: {version}",
            f"{symbol} Certifikat t.o.m. {expires:%Y-%m-%d} (hela dagar kvar: {days})"]


def normalize_paths(paths, host):
    """Gör vanliga sökvägar användbara utan att gå utanför domänen."""
    urls = []
    for raw in paths:
        path = raw.strip()
        if not path:
            continue
        if ("?" in path or "#" in path or "\\" in path or
                path.startswith("//") or "://" in path or "@" in path):
            raise ValueError("Undersidor ska vara enkla sökvägar utan frågeparametrar.")
        path = "/" + path.strip("/") + "/"
        url = urljoin(f"https://{host}/", path)
        if not same_host(url, host):
            raise ValueError("Undersidan är inte på samma domän.")
        if url not in urls:
            urls.append(url)
    if len(urls) > MAX_PAGES - 1:
        raise ValueError("Högst fyra extra undersidor får anges.")
    return urls


def header_state(headers):
    """Status är en indikation, inte ett bevis på säkerhet eller sårbarhet."""
    hsts = headers.get("Strict-Transport-Security", "")
    csp = headers.get("Content-Security-Policy", "")
    report_only = headers.get("Content-Security-Policy-Report-Only", "")
    xcto = headers.get("X-Content-Type-Options", "")
    ref = headers.get("Referrer-Policy", "")
    xfo = headers.get("X-Frame-Options", "")
    return {
        "HSTS": bool(hsts),
        "CSP (aktiv)": bool(csp),
        "X-Content-Type-Options": xcto.strip().lower() == "nosniff",
        "Referrer-Policy": bool(ref),
        "Inbäddningsskydd": ("frame-ancestors" in csp.lower() or
                             xfo.strip().upper() in ("DENY", "SAMEORIGIN")),
    }


EXPLANATIONS = {
    "HSTS": "HSTS hjälper webbläsaren att använda HTTPS.",
    "CSP (aktiv)": "CSP begränsar möjliga källor för skript och annat innehåll; kräver testning i WordPress.",
    "X-Content-Type-Options": "nosniff minskar vissa risker från felaktiga MIME-typer.",
    "Referrer-Policy": "Styr hur mycket adressinformation som skickas vid navigering.",
    "Inbäddningsskydd": "CSP frame-ancestors eller X-Frame-Options kan minska clickjacking-risker.",
}



# RWB Security Advisor: lokala, regelbaserade råd – ingen extern AI-tjänst.
# Råden är inte bevis för sårbarheter eller ett intrång.
ADVICE = {
    "HSTS": (
        "Medel", "Kontrollera om HSTS bör aktiveras på webbservern. Säkerställ först att alla berörda värdnamn stöder HTTPS; includeSubDomains och preload kräver särskild eftertanke."
    ),
    "CSP (aktiv)": (
        "Planerad förbättring", "Börja med Content-Security-Policy-Report-Only och analysera rapporter. Anpassa därefter regler för WordPress-tema och tillägg innan en aktiv policy införs."
    ),
    "X-Content-Type-Options": (
        "Enkel förbättring", "Överväg HTTP-headern X-Content-Type-Options: nosniff. Verifiera att webbservern skickar korrekta MIME-typer för skript och stilmallar."
    ),
    "Referrer-Policy": (
        "Enkel förbättring", "Överväg Referrer-Policy: strict-origin-when-cross-origin. Kontrollera om externa integrationer behöver annan hantering."
    ),
    "Inbäddningsskydd": (
        "Rekommenderad", "Överväg CSP-direktivet frame-ancestors 'self' (eller 'none') eller X-Frame-Options: SAMEORIGIN/DENY. Kontrollera först om inbäddning behövs."
    ),
}


def advisor_rows(scan):
    """Returnera strukturerade förslag från de faktiskt granskade sidorna."""
    if not isinstance(scan, dict):
        return []
    entries = []
    pages = scan.get("pages", {})
    if not isinstance(pages, dict):
        return entries
    for url, states in pages.items():
        if not isinstance(states, dict):
            continue
        for key, value in states.items():
            if key in ADVICE and value is False:
                priority, recommendation = ADVICE[key]
                entries.append((str(url), key, priority, recommendation))
    return entries


def advisor_text(scan):
    entries = advisor_rows(scan)
    lines = ["", "RWB SECURITY ADVISOR – LOKALA REKOMMENDATIONER",
             "Regelbaserat beslutsstöd, inte AI-analys eller bevis för intrång."]
    if not scan.get("pages"):
        lines.append("Ingen färdig sidkontroll finns att analysera.")
    elif not entries:
        lines.append("Inga saknade skydd identifierades i de kontrollerade kategorierna.")
        lines.append("Det betyder inte att webbplatsen är helt säker.")
    else:
        for i, (url, key, priority, recommendation) in enumerate(entries, 1):
            lines.extend([f"{i}. {key} [{priority}]", f"   Sida: {url}",
                          f"   Råd: {recommendation}"])
    if scan.get("cert_days") is not None:
        days = scan["cert_days"]
        if days < 14:
            lines.append("BRÅDSKANDE: TLS-certifikatet har mindre än 14 dagar kvar eller har gått ut. Kontrollera förnyelsen.")
        elif days < 30:
            lines.append("Planera TLS-certifikatets förnyelse: mindre än 30 dagar kvar.")
    lines.extend(["", "Prioriteringar är vägledande, inte en säkerhetspoäng.",
                  "Ändra inte produktionskonfiguration utan backup och funktionstest.",
                  "Kontrollera alltid instruktioner med webbhotellet före serverändringar."])
    return "\n".join(lines)


def history_load():
    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    except (OSError, ValueError, TypeError):
        pass
    return []


def history_save(records):
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = HISTORY_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(HISTORY_PATH)



# Exporterna innehåller endast lokal, användarstyrd säkerhetshistorik.
EXPORT_ROOT = Path.home() / "RWB-CyberGuard"
REPORT_DIR = EXPORT_ROOT / "Rapporter"
EXPORT_DIR = EXPORT_ROOT / "Historik"
EXCEL_DIR = EXPORT_ROOT / "Excelrapporter"
BACKUP_DIR = EXPORT_ROOT / "Sakerhetskopior"


def create_export_dirs():
    required_dirs = (
        REPORT_DIR,
        EXPORT_DIR,
        EXCEL_DIR,
        BACKUP_DIR,
        EXPORT_ROOT / "DemoLoggfiler",
        EXPORT_ROOT / "Ikoner",
        EXPORT_ROOT / "Test_Server",
        EXPORT_ROOT / "Webbadresser",
    )

    for directory in required_dirs:
        directory.mkdir(parents=True, exist_ok=True)


# Alpha 6: lokal webbplatslista. Ingen schemalagd eller automatisk skanning.
WEBSITES_PATH = EXPORT_ROOT / "Webbadresser" / "webbadresser.json"


def validate_website(name, url, allow_legacy=False):
    name = name.strip()
    if not name or len(name) > 100 or any(ord(ch) < 32 for ch in name):
        raise ValueError("Webbplatsnamnet måste vara 1–100 tecken utan kontrolltecken.")
    url = normalize_url(url, allow_legacy=allow_legacy)
    if len(url) > 2048:
        raise ValueError("Webbadressen får vara högst 2048 tecken.")
    return name, url


def load_websites():
    """Läs lokal metadata. Ogiltig befintlig fil skrivs aldrig över automatiskt."""
    if not WEBSITES_PATH.exists():
        return []
    data = json.loads(WEBSITES_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("webbplatser"), list):
        raise ValueError("Okänt format på webbadresser.json – filen har inte ändrats.")
    sites, seen = [], set()
    for item in data["webbplatser"]:
        if not isinstance(item, dict):
            raise ValueError("Felaktig post i webbadresser.json.")
        name, url = validate_website(
        item.get("namn", ""),
        item.get("url", ""),
        allow_legacy=True
        )
        if url in seen:
            raise ValueError("Dubbletter i webbadresser.json måste åtgärdas manuellt.")
        if not isinstance(item.get("bevakning"), bool) or item.get("kontrollniva") != 1:
            raise ValueError("Okända inställningar i webbadresser.json.")
        seen.add(url)
        sites.append({"namn": name, "url": url,
                      "bevakning": item["bevakning"], "kontrollniva": 1})
    return sites


def save_websites(sites):
    WEBSITES_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {"version": 1, "webbplatser": sites}
    tmp = WEBSITES_PATH.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(WEBSITES_PATH)
    finally:
        if tmp.exists():
            tmp.unlink()


def short_url(url, max_len=50):
    return url if len(url) <= max_len else url[:max_len - 3] + "..."


class HoverTip:
    """Visa hela URL:en vid muspekaren utan extra tredjepartsbibliotek."""
    def __init__(self, widget, text_getter):
        self.widget, self.text_getter, self.popup = widget, text_getter, None
        self.job = None
        widget.bind("<Enter>", self.enter, add="+")
        widget.bind("<Leave>", self.leave, add="+")
        widget.bind("<ButtonPress>", self.leave, add="+")

    def enter(self, event=None):
        self.leave()
        self.job = self.widget.after(700, self.show)

    def show(self):
        self.job = None
        text = self.text_getter()
        if not text or not self.widget.winfo_exists():
            return
        self.popup = tk.Toplevel(self.widget)
        self.popup.wm_overrideredirect(True)
        self.popup.wm_geometry(f"+{self.widget.winfo_rootx()}+{self.widget.winfo_rooty()+self.widget.winfo_height()+4}")
        ttk.Label(self.popup, text=text, padding=7, wraplength=680).pack()

    def leave(self, event=None):
        if self.job is not None:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.popup is not None:
            self.popup.destroy()
            self.popup = None


def dated_name(prefix, extension):
    stamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S")
    path = (REPORT_DIR if extension == "txt" else EXCEL_DIR if extension == "xlsx" else EXPORT_DIR) / f"{prefix}_{stamp}.{extension}"
    counter = 2
    while path.exists():
        path = path.with_name(f"{prefix}_{stamp}_{counter}.{extension}")
        counter += 1
    return path


def safe_cell(value):
    """Skydda kalkylblad och CSV från formeltolkning av inmatade URL:er."""
    if value is None:
        return ""
    result = str(value)
    if result.lstrip().startswith(("=", "+", "-", "@")):
        result = "'" + result
    return result.replace("\x00", "")[:32000]


def export_rows(records):
    overview = [["Tidpunkt UTC", "Domän", "Antal sidor", "Identifierade skydd",
                 "Att granska", "TLS-certifikat t.o.m.", "Dagar kvar vid kontroll"]]
    page_rows = [["Tidpunkt UTC", "Domän", "Sida", "HSTS", "CSP (aktiv)",
                  "X-Content-Type-Options", "Referrer-Policy", "Inbäddningsskydd"]]
    changes = [["Tidpunkt UTC", "Domän", "Förändring", "Beskrivning"]]
    previous_by_host = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        host = str(record.get("host", ""))
        pages = record.get("pages", {})
        if not isinstance(pages, dict):
            continue
        count, passed, missing = history_summary(record)
        when = record.get("time", "")
        overview.append([when, host, count, passed, missing,
                         record.get("tls_expiry", ""), record.get("cert_days", "")])
        for url, states in sorted(pages.items()):
            if not isinstance(states, dict):
                continue
            def flag(name):
                val = states.get(name)
                return "Ja" if val is True else ("Nej" if val is False else "Ej mätt")
            page_rows.append([when, host, url] + [flag(name) for name in EXPLANATIONS])
        prior = previous_by_host.get(host)
        if prior is not None:
            for line in compare_results(prior, record):
                if line != "Inga förändringar i de jämförbara headerkontrollerna.":
                    changes.append([when, host, "Headers/sidor", line])
            for line in compare_certificates(prior, record):
                if line not in ("Certifikatets utgångsdatum är oförändrat.",
                                "Certifikatet kunde inte jämföras med tidigare kontroll.",
                                "Ingen tidigare jämförbar certifikatinformation finns."):
                    changes.append([when, host, "Certifikat", line])
        previous_by_host[host] = record
    return [("Översikt", overview), ("Sidkontroller", page_rows), ("Förändringar", changes)]


def write_csv_exports(records):
    create_export_dirs()
    base = dated_name("CyberGuard_Historik", "csv")
    outputs = []
    for sheet_name, rows in export_rows(records):
        path = base.with_name(base.stem + "_" + {
            "Översikt": "Oversikt", "Sidkontroller": "Sidkontroller",
            "Förändringar": "Forandringar"}[sheet_name] + ".csv")
        with path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.writer(file, delimiter=";")
            writer.writerows([[safe_cell(value) for value in row] for row in rows])
        outputs.append(path)
    return outputs


def xlsx_col(number):
    result = ""
    while number:
        number, rem = divmod(number - 1, 26)
        result = chr(65 + rem) + result
    return result


def swedish_time(value):
    """Visa sparade UTC-tider i datorns lokala tidszon."""
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OverflowError):
        return str(value or "")


def polished_rows(records):
    sheets = export_rows(records)
    result = []
    for title, rows in sheets:
        new_rows = [list(row) for row in rows]
        if new_rows:
            new_rows[0][0] = "Tidpunkt (lokal tid)"
        for row in new_rows[1:]:
            if row:
                row[0] = swedish_time(row[0])
        result.append((title, new_rows))
    return result


def dashboard_rows(records):
    """Grafiskt diagram utan externa Python-bibliotek, normaliserat per sida."""
    rows = [[f"RWB CYBERGUARD SWEDEN {VERSION} – SÄKERHETSHISTORIK"],
            ["Diagrammet visar andel identifierade skydd per kontrollerad sida; ingen riskpoäng."],
            ["Grönt = identifierat; orange = att granska. Historiken kan omfatta olika antal sidor."],
            [], ["Tidpunkt (lokal)", "Domän", "Sidor", "Skydd / sida", "Att granska / sida",
                 "Andel skydd (%)", "Visuell översikt (20 steg)"]]
    for r in records:
        if not isinstance(r, dict):
            continue
        n, passed, missing = history_summary(r)
        if not n:
            continue
        denominator = passed + missing
        fraction = passed / denominator if denominator else 0
        cells = min(20, max(0, round(20 * fraction)))
        rows.append([swedish_time(r.get("time", "")), str(r.get("host", "")), n,
                     round(passed / n, 2), round(missing / n, 2),
                     round(fraction * 100, 1), ""] + [1] * cells + [0] * (20-cells))
    return rows


def xlsx_sheet_xml(rows, kind="normal"):
    """OOXML med frysta rubriker, bra kolumnbredder och färgkodning."""
    dashboard = kind == "diagram"
    header_row = 5 if dashboard else 1
    widths = ([24, 25, 12, 16, 20, 18, 21] + [3.2]*20 if dashboard else
              ([25, 32, 85, 17] if kind in ("Sammanfattning", "Kontroller", "Rapporttext") else
              ([23, 28, 14, 19, 18, 22, 20] if kind == "Översikt" else
               [23, 26, 57, 16, 19, 24, 20, 20] if kind == "Sidkontroller" else
               [23, 26, 20, 90])))
    lines = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
             f'<sheetViews><sheetView workbookViewId="0"><pane ySplit="{header_row}" topLeftCell="A{header_row+1}" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>',
             '<sheetFormatPr defaultRowHeight="20"/>', '<cols>']
    for i, width in enumerate(widths, 1):
        lines.append(f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>')
    lines.append('</cols><sheetData>')
    for ri, row in enumerate(rows, 1):
        lines.append(f'<row r="{ri}"' + (' ht="29" customHeight="1"' if dashboard and ri == 1 else '') + '>')
        for ci, value in enumerate(row, 1):
            ref = f'{xlsx_col(ci)}{ri}'
            style = 1 if ri == header_row else (5 if dashboard and ri == 1 else (6 if dashboard and ri in (2,3) else (2 if ri%2 == 0 else 0)))
            if dashboard and ri > header_row and ci > 7:
                style = 3 if value == 1 else 4
                value = ""
            elif kind == "Sidkontroller" and ri > 1 and ci >= 4:
                style = 3 if value == "Ja" else (4 if value == "Nej" else 2)
            elif kind == "Översikt" and ri > 1 and ci == 5:
                style = 4
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                lines.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
            else:
                value = safe_cell(value)
                lines.append(f'<c r="{ref}" t="inlineStr" s="{style}"><is><t xml:space="preserve">{xml_escape(value)}</t></is></c>')
        lines.append('</row>')
    lines.append('</sheetData>')
    if dashboard:
        lines.append('<mergeCells count="3"><mergeCell ref="A1:K1"/><mergeCell ref="A2:K2"/><mergeCell ref="A3:K3"/></mergeCells>')
    lines.append(f'<autoFilter ref="A{header_row}:{xlsx_col(7 if dashboard else len(rows[0]))}{max(header_row,len(rows))}"/>')
    lines.append('</worksheet>')
    return ''.join(lines)


def write_workbook_xlsx(path, sheets):
    """Skriv en Excel-arbetsbok med Pythons standardbibliotek."""
    namespace = 'http://schemas.openxmlformats.org/'
    content_types = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
                     '<Default Extension="xml" ContentType="application/xml"/>',
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
                     '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(1, len(sheets)+1):
        content_types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append('</Types>')
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                + ''.join(f'<sheet name="{xml_escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
                          for i,(name,_) in enumerate(sheets,1)) + '</sheets></workbook>')
    relationships = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                     + ''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(sheets)+1))
                     + f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                     + '</Relationships>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="4"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font>'
              '<font><color rgb="FF334155"/><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><color rgb="FF123047"/><sz val="15"/><name val="Calibri"/></font></fonts>'
              '<fills count="6"><fill><patternFill patternType="none"/></fill>'
              '<fill><patternFill patternType="gray125"/></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FF17466A"/></patternFill></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FFF0F5FA"/></patternFill></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FFD6F0DF"/></patternFill></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FFFFE4BD"/></patternFill></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="7"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" applyFont="1" applyFill="1"/>'
              '<xf numFmtId="0" fontId="2" fillId="3" borderId="0" applyFill="1"/>'
              '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" applyFill="1"/>'
              '<xf numFmtId="0" fontId="0" fillId="5" borderId="0" applyFill="1"/>'
              '<xf numFmtId="0" fontId="3" fillId="3" borderId="0" applyFont="1" applyFill="1"/>'
              '<xf numFmtId="0" fontId="2" fillId="0" borderId="0"/></cellXfs></styleSheet>')
    with ZipFile(path, 'w', ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',''.join(content_types))
        z.writestr('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')
        z.writestr('xl/workbook.xml',workbook)
        z.writestr('xl/_rels/workbook.xml.rels',relationships)
        z.writestr('xl/styles.xml',styles)
        for i,(name,rows) in enumerate(sheets,1):
            z.writestr(f'xl/worksheets/sheet{i}.xml', xlsx_sheet_xml(rows, 'diagram' if name == 'Diagram' else name))
    return path


def write_xlsx_export(records):
    """Exportera hela historiken till XLSX, kompatibel med v1.6."""
    create_export_dirs()
    path = dated_name("CyberGuard_Historik", "xlsx")
    sheets = [("Diagram", dashboard_rows(records))] + polished_rows(records)
    return write_workbook_xlsx(path, sheets)


def report_xlsx_sheets(report):
    """Gör om EXAKT den synliga rapporttexten till läsbara Excel-flikar.

    Ingen ny nätverksbegäran görs; även ett misslyckat test kan exporteras.
    """
    lines = report.splitlines()
    heading = 'Översikt'
    summary = [["Fält", "Värde", "Kommentar", "Status"]]
    details = [["Avsnitt", "Kontroll / fält", "Resultat / förklaring", "Status"]]
    raw = [["Rad", "Avsnitt", "Originaltext", "Status"]]
    for number, line in enumerate(lines, 1):
        trimmed = line.strip()
        if not trimmed:
            continue
        if trimmed in ("TLS OCH CERTIFIKAT", "SAMMANFATTNING",
                       "JÄMFÖRELSE MED FÖREGÅENDE KONTROLL",
                       "HTTP OCH SÄKERHETSHEADERS") or trimmed.startswith("SIDA "):
            heading = trimmed
            continue
        status = ("OK" if trimmed.startswith("✓") else
                  "Granska" if trimmed.startswith("!") else
                  "Fel" if trimmed.startswith("✗") else "Info")
        cleaned = trimmed.lstrip("✓!✗→ ").strip()
        key, sep, value = cleaned.partition(": ")
        if not sep:
            key, value = "Information", cleaned
        details.append([heading, key, value, status])
        raw.append([str(number), heading, trimmed, status])
        if trimmed.startswith(("Kontrollerad:", "Startadress:", "Giltig TLS", "✓ Certifikat", "✓ Giltig TLS", "Identifierade skydd:",
                               "Rekommendationer att granska:", "Felaktiga/misslyckade sidkontroller:")):
            summary.append([key, value, heading, status])
    summary.append(["Tolkning", "Enbart kontrollerade sidor", "Saknade headers är inte bevis för intrång.", "Info"])
    summary.append(["Program", f"RWB CyberGuard Sweden {VERSION}", "Passiv webbplatskontroll med tillstånd.", "Info"])
    # Rådgivarens rader följer med den individuella Excel-rapporten.
    advice_sheet = [["Prioritet", "Kontroll", "Sida", "Rekommendation"]]
    in_advisor = False
    current_key = ""
    current_priority = ""
    current_url = ""
    for line in lines:
        if line.startswith("RWB SECURITY ADVISOR"):
            in_advisor = True
            continue
        if not in_advisor:
            continue
        match = re.match(r"^\d+\. (.*?) \[(.*?)\]$", line)
        if match:
            current_key, current_priority = match.group(1, 2)
        elif line.startswith("   Sida: "):
            current_url = line.split(": ", 1)[1]
        elif line.startswith("   Råd: "):
            advice_sheet.append([current_priority, current_key, current_url, line.split(": ", 1)[1]])
    return [("Sammanfattning", summary), ("Kontroller", details), ("Rådgivare", advice_sheet), ("Rapporttext", raw)]


def write_report_xlsx(report):
    """Spara aktuell individuell säkerhetsrapport i daterad Excel-fil."""
    if not report or not report.strip():
        raise ValueError("Det finns ingen rapport att exportera ännu.")
    create_export_dirs()
    path = dated_name("CyberGuard_Rapport", "xlsx")
    return write_workbook_xlsx(path, report_xlsx_sheets(report))


def save_dated_report(report):
    create_export_dirs()
    path = dated_name("CyberGuard_Rapport", "txt")
    path.write_text(report.rstrip() + "\n", encoding="utf-8")
    return path


def backup_history():
    create_export_dirs()
    if not HISTORY_PATH.exists():
        return None
    stamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S")
    path = BACKUP_DIR / f"history_{stamp}.json"
    index = 2
    while path.exists():
        path = BACKUP_DIR / f"history_{stamp}_{index}.json"
        index += 1
    path.write_bytes(HISTORY_PATH.read_bytes())
    return path

def normalize_history_page(url):
    """Jämför root-URL med/utan slash; rör inte sparad historik."""
    parts = urlsplit(url)
    if parts.path in ("", "/") and not parts.query and not parts.fragment:
        return parts._replace(path="/").geturl()
    return url


def normalized_page_states(record):
    pages = record.get("pages", {})
    if not isinstance(pages, dict):
        return {}
    return {normalize_history_page(url): states for url, states in pages.items()}


def compare_results(previous, current):
    if previous is None:
        return ["Ingen tidigare jämförbar kontroll finns i historiken."]
    old = normalized_page_states(previous)
    new = normalized_page_states(current)
    messages = []
    for url in sorted(set(old) & set(new)):
        before, after = old[url], new[url]
        if not isinstance(before, dict) or not isinstance(after, dict):
            continue
        for key in EXPLANATIONS:
            if key not in before or key not in after:
                continue
            if before[key] != after[key]:
                action = "Nytt skydd upptäckt" if after[key] else "Skydd saknas nu"
                messages.append(f"{'✓' if after[key] else '!'} {action}: {key} ({url})")
    for url in sorted(set(new) - set(old)):
        messages.append(f"Ny kontrollerad sida: {url}")
    for url in sorted(set(old) - set(new)):
        messages.append(f"Tidigare sida ej kontrollerad nu: {url}")
    return messages or ["Inga förändringar i de jämförbara headerkontrollerna."]


def history_for(host):
    """Samtliga tillgängliga kontroller för en värd i tidsordning."""
    return [r for r in history_load() if r.get("host") == host and isinstance(r.get("pages"), dict)]


def history_summary(record):
    pages = record.get("pages", {})
    passed = sum(v is True for page in pages.values() if isinstance(page, dict)
                 for v in page.values())
    missing = sum(v is False for page in pages.values() if isinstance(page, dict)
                  for v in page.values())
    return len(pages), passed, missing


def compare_certificates(previous, current):
    if not previous:
        return ["Ingen tidigare jämförbar certifikatinformation finns."]
    old = previous.get("tls_expiry")
    new = current.get("tls_expiry")
    if not old or not new:
        return ["Certifikatet kunde inte jämföras med tidigare kontroll."]
    if old != new:
        return [f"{'✓' if new > old else '!'} Certifikatets utgångsdatum har ändrats: {old} → {new}."]
    return ["Certifikatets utgångsdatum är oförändrat."]


def check_site(home_url, paths):
    parts = urlsplit(home_url)
    host = parts.hostname
    urls = list(dict.fromkeys([home_url] + normalize_paths(paths, host)))
    previous = next((r for r in reversed(history_load()) if r.get("host") == host), None)
    report = [f"RWB CYBERGUARD SWEDEN {VERSION}",
              f"Kontrollerad: {dt.datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}",
              f"Startadress: {home_url}", "", "TLS OCH CERTIFIKAT"]
    scan = {"host": host, "time": dt.datetime.now(dt.timezone.utc).isoformat(), "pages": {}}
    try:
        tls_lines = tls_info(host)
        report.extend(tls_lines)
        for line in tls_lines:
            if "Certifikat t.o.m." in line:
                scan["tls_expiry"] = line.split("Certifikat t.o.m. ", 1)[1][:10]
                try:
                    days = int(line.split("hela dagar kvar: ", 1)[1].split(")")[0])
                    scan["cert_days"] = days
                    if days < 0:
                        report.append("✗ Certifikatet är utgånget.")
                    elif days < 14:
                        report.append("! Certifikatet går ut inom 14 dagar – förnya snarast.")
                    elif days < 30:
                        report.append("! Certifikatet går ut inom 30 dagar – planera förnyelse.")
                except (ValueError, IndexError):
                    pass
    except (OSError, ssl.SSLError, ValueError) as exc:
        report.append(f"✗ TLS-kontroll misslyckades: {exc}")
        report.append("Ingen historik sparades eftersom TLS-kontrollen misslyckades.")
        return "\n".join(report)
    ok_count = warn_count = error_count = 0
    for i, url in enumerate(urls, 1):
        report.extend(["", f"SIDA {i}/{len(urls)}: {url}"])
        try:
            final_url, status, headers = get_page(url, host)
            if final_url != url:
                report.append(f"→ Omdirigerad inom domänen till: {final_url}")
            report.append(f"HTTP-status: {status}")
            if status >= 400:
                report.append("! HTTP-fel: sidan kan inte betraktas som normalt tillgänglig.")
                error_count += 1
                continue
            state = header_state(headers)
            scan["pages"][url] = state
            for key, present in state.items():
                if present:
                    report.append(f"✓ {key}: identifierat på detta svar.")
                    ok_count += 1
                else:
                    report.append(f"! {key}: saknas/ej identifierat. {EXPLANATIONS[key]}")
                    warn_count += 1
            report.append("Obs: Närvarande headers kan ändå ha otillräcklig konfiguration.")
        except (OSError, ssl.SSLError, URLError, ValueError) as exc:
            report.append(f"✗ Kunde inte kontrollera sidan: {exc}")
            error_count += 1
    report.extend(["", "SAMMANFATTNING", f"Identifierade skydd: {ok_count}",
                   f"Rekommendationer att granska: {warn_count}",
                   f"Felaktiga/misslyckade sidkontroller: {error_count}",
                   "Antalen gäller kontroller per sida, inte upptäckta sårbarheter.",
                   "", "JÄMFÖRELSE MED FÖREGÅENDE KONTROLL"])
    if scan["pages"]:
        report.extend(compare_results(previous, scan))
        report.extend(compare_certificates(previous, scan))
        try:
            records = history_load()
            records.append(scan)
            history_save(records)
            report.append(f"Historik sparad lokalt: {HISTORY_PATH}")
        except OSError as exc:
            report.append(f"! Historik kunde inte sparas: {exc}")
    else:
        report.append("Ingen historik sparades eftersom inga sidor kunde kontrolleras.")
    report.append(advisor_text(scan))
    report.extend(["", "Kontrollen avslutad.",
                   "Saknade headers är förbättringsförslag, inte bevis för intrång.",
                   "Ingen intrångstestning, autentisering eller aktiv sårbarhetsskanning utförd."])
    return "\n".join(report)



# Referenser: https://www.php.net/supported-versions.php och
# https://www.php.net/archive/2026.php#2026-10-21-5
# Tabellen är daterad 2026-10-22 och måste ses över vid framtida utgåvor.
PHP_SUPPORT_END = {
    "8.2": "2026-12-31", "8.3": "2027-12-31",
    "8.4": "2028-12-31", "8.5": "2029-12-31",
}
PHP_ACTIVE_END = {
    "8.2": "2024-12-31", "8.3": "2025-12-31",
    "8.4": "2026-12-31", "8.5": "2027-12-31",
}
PHP2SHELL_MIN_FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}


def inspect_php_version(value, vendor_patch=False, today=None):
    """Statisk rådgivning om ägarangiven PHP-version – ingen fjärrdetektering."""
    value = value.strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError("Ange en fullständig PHP-version, exempelvis 8.4.27.")
    major, minor, patch = map(int, match.groups())
    series = f"{major}.{minor}"
    today = today or dt.date.today()
    lines = [f"RWB PHP SECURITY INSPECTOR – version {VERSION}",
             f"PHP-version (angiven av webbplatsägaren): {value}",
             f"Bedömd datum: {today:%Y-%m-%d}",
             "Källa för version: MANUELL INMATNING – ej verifierad via servern.", ""]
    if series in PHP_SUPPORT_END:
        support_end = dt.date.fromisoformat(PHP_SUPPORT_END[series])
        active_end = dt.date.fromisoformat(PHP_ACTIVE_END[series])
        if today > support_end:
            lines.append(f"VARNING: PHP {series} saknar ordinarie säkerhetsstöd sedan {support_end}.")
        elif today > active_end:
            lines.append(f"STATUS: PHP {series} får endast kritiska säkerhetsrättningar fram till {support_end}.")
        else:
            lines.append(f"STATUS: PHP {series} är under aktivt stöd fram till {active_end}.")
            lines.append(f"Säkerhetsstöd planerat till {support_end}.")
    elif (major, minor) < (8, 2):
        lines.append("VARNING: Denna äldre PHP-serie saknar ordinarie stöd från PHP-projektet.")
    else:
        lines.append("OKÄNT: Supportstatus för denna PHP-serie finns inte i programmets daterade tabell.")
        lines.append("Kontrollera aktuellt läge på php.net/supported-versions.php.")
    lines.extend(["", "PHP2SHELL – CVE-2026-109618 OCH CVE-2026-109619 (KÄLLKONTROLL ÅTERSTÅR)"])
    threshold = PHP2SHELL_MIN_FIXED.get(series)
    if threshold is not None:
        if patch >= threshold:
            lines.append(f"✓ {value} är minst den i programmets ännu ej externt verifierade tabell angivna utgåvan {series}.{threshold}.")
            lines.append("OBS: Detta visar versionsjämförelse, inte att serverns binär har verifierats.")
        else:
            lines.append(f"! {value} är äldre än den i programmets ännu ej externt verifierade tabell angivna utgåvan {series}.{threshold}.")
            lines.append("Kontakta webbhotellet och begär verifiering av installerade säkerhetsrättningar.")
    else:
        lines.append("PHP-projektet publicerar inte ordinarie rättade utgåvor i denna äldre/okända serie.")
        lines.append("Leverantörens säkerhetsbackporter kan behöva kontrolleras separat.")
    if vendor_patch:
        lines.extend(["", "LEVERANTÖRSRÄTTNINGAR: Webbplatsägaren uppger att webbhotellet",
                      "installerar särskilda/backporterade patchar; detta har INTE verifierats.",
                      "Be leverantören ange rättningsdatum och vilka CVE som omfattas."])
    lines.extend(["", "Rekommendationer:",
                  "• Verifiera PHP-versionen i WordPress: Verktyg > Webbplatshälsa > Info > Server.",
                  "• Be webbhotellet bekräfta installation och backportstatus.",
                  "• Uppdatera WordPress och tillägg och ta säkerhetskopia före ändringar.",
                  "• En extern HTTPS-kontroll kan normalt inte fastställa aktiv PHP-version.",
                  "• Lita inte på en eventuell X-Powered-By-header som bevis för installerad version.", "",
                  "Källor: https://www.php.net/supported-versions.php",
                  "https://www.php.net/archive/2026.php#2026-10-21-5",
                  "Tabellens referensdatum: 2026-10-22. Kontrollera uppdateringar hos PHP-projektet."])
    return "\n".join(lines)

# PHP-projektets informationsvarning 23 oktober 2026.
# https://www.php.net/archive/2026.php
# Detta är en MANUELL konfigurationsbedömning, inte en extern avläsning.
PHP_SESSION_SOURCE = "https://www.php.net/archive/2026.php"
PHP_SESSION_CVE = "CVE-2026-115560"


def inspect_php_session(upload_enabled="unknown", configured_handler="unknown", runtime_switch="unknown"):
    """Bedöm dokumenterade riskvillkor försiktigt. Parametrarna är ägaruppgifter."""
    if upload_enabled not in ("unknown", "yes", "no"):
        raise ValueError("Ogiltigt värde för upload progress")
    if configured_handler not in ("unknown", "php", "php_binary", "php_serialize", "other"):
        raise ValueError("Ogiltigt värde för session.serialize_handler")
    if runtime_switch not in ("unknown", "yes", "no"):
        raise ValueError("Ogiltigt värde för runtime-byte")
    labels = {"unknown": "Okänt / ej verifierat", "yes": "Ja (manuellt uppgivet)",
              "no": "Nej (manuellt uppgivet)", "php": "php", "php_binary": "php_binary",
              "php_serialize": "php_serialize", "other": "Annan serialiserare"}
    lines = ["", "PHP SESSION CONFIGURATION ADVISOR – CVE-2026-115560",
             "Källa: PHP-projektets informationsvarning 2026-10-23",
             "Bedömningsmetod: MANUELLT ANGIVNA UPPGIFTER, inte verifierade av programmet.",
             f"session.upload_progress.enabled: {labels[upload_enabled]}",
             f"session.serialize_handler (grundkonfiguration): {labels[configured_handler]}",
             f"Byte via ini_set() till 'php' före session_start(): {labels[runtime_switch]}"]
    risky_handlers = {"php_binary", "php_serialize"}
    if upload_enabled == "no":
        status = "ANGIVET SKYDD: Upload progress avstängd; det dokumenterade riskvillkoret saknas."
    elif runtime_switch == "no":
        status = "ANGIVET SKYDD: Inget byte av serialiserare före session_start(); den beskrivna kedjan saknas."
    elif configured_handler in ("php", "other"):
        status = "ANGIVET SKYDD: Grundinställningen är inte någon av de två berörda serialiserarna."
    elif upload_enabled == "yes" and configured_handler in risky_handlers and runtime_switch == "yes":
        status = "VARNING: Alla tre angivna riskvillkor sammanfaller. Kontakta webbhotell/utvecklare."
    else:
        status = "OKLART: Uppgifter saknas; detta är INTE ett säkerhetsgodkännande."
    lines += ["Bedömning: " + status, "Rekommendation: be webbhotellet kontrollera PHP-konfiguration och applikationskod.",
              "PHP-projektets tillfälliga rekommendation (2026-10-23): session.upload_progress.enabled=0",
              "Ändra inte produktion utan leverantörens godkännande och funktionstest.",
              "En aktiverad funktion ensam är INTE bevis på sårbarhet eller intrång.",
              "Verifiera nya rättningar och råd hos " + PHP_SESSION_SOURCE]
    return "\n".join(lines)


def export_php_xlsx(php_report, php_version, hosting_patches=False):
    """Egen kalkylbladsrapport för PHP, utan att ändra webbplatshistoriken."""
    if not php_report.strip():
        raise ValueError("Det finns ingen PHP-analys att exportera.")
    create_export_dirs()
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines = php_report.splitlines()
    details = []
    category = "Information"
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        if raw.endswith(":") or raw.startswith("PHP2SHELL") or raw.startswith("PHP SESSION CONFIGURATION ADVISOR"):
            category = raw.rstrip(":")
        details.append([category, raw])
    summary = [
        ["Fält", "Värde"],
        ["Rapport", "RWB PHP Security Inspector"],
        ["Version program", VERSION],
        ["Exporterad", now],
        ["PHP-version (manuellt angiven)", php_version.strip()],
        ["Källa", "Manuell uppgift från webbplatsägaren"],
        ["Webbhotellets specialpatchar uppgivna", "Ja (ej verifierat)" if hosting_patches else "Nej / ej uppgivet"],
        ["Kontrollmetod", "Versionsbedömning – inte fjärrskanning av PHP"],
        ["Viktigt", "PHP-version och installerade säkerhetsrättningar är inte automatiskt verifierade"],
    ]
    path = dated_name("CyberGuard_PHP_Rapport", "xlsx")
    return write_workbook_xlsx(path, [
        ("PHP Sammanfattning", summary),
        ("PHP Bedömning", [["Avsnitt", "Information"]] + details),
        ("Rapporttext", [["Rad", "Fullständig PHP-rapport"]] + [[i, value] for i, value in enumerate(lines, 1)]),
    ])


# --- Version 2.1: lokal logganalys och tidiga varningar ---
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_LOG_BYTES = 12 * 1024 * 1024
MAX_FEED_BYTES = 8 * 1024 * 1024
ACCESS_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[([^]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?:\d+|-)'
)
SUSPICIOUS_PATHS = (
    '/.env', '/.git/', '/wp-config.php', '/vendor/phpunit/',
    '/phpinfo.php', '/xmlrpc.php', '/.aws/', '/actuator/env'
)


def analyse_access_log(content):
    """Offline, defensiv logganalys. IP och User-Agent är opålitliga indikatorer."""
    from collections import Counter, defaultdict
    from datetime import datetime, timedelta
    hits, codes, ips, examples, clients = Counter(), Counter(), Counter(), [], Counter()
    sensitive_by_ip, denied_by_ip, limited_by_ip = Counter(), Counter(), Counter()
    moments = defaultdict(list)
    parsed = 0
    invalid = 0
    for raw in content.splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        m = ACCESS_PATTERN.match(raw)
        if not m:
            invalid += 1
            continue
        parsed += 1
        ip, request, status = m.group('ip'), m.group('request'), int(m.group('status'))
        codes[status] += 1
        ips[ip] += 1
        parts = request.split(' ')
        path = parts[1].split('?')[0].lower() if len(parts) >= 2 else ''
        # Combined-formatets User-Agent är sista citerade fältet.
        tail = raw[m.end():]
        quoted = re.findall(r'"([^"\n]*)"', tail)
        ua = quoted[-1] if quoted else ''
        if 'bot' in ua.lower() or 'scanner' in ua.lower() or 'curl/' in ua.lower() or 'python-requests' in ua.lower():
            clients['Automatiserad klient (uppgiven)'] += 1
        elif 'Chrome/' in ua:
            clients['Chrome'] += 1
        elif 'Safari/' in ua:
            clients['Safari'] += 1
        elif 'Firefox/' in ua:
            clients['Firefox'] += 1
        else:
            clients['Okänd/annan'] += 1
        flags = []
        if any(path.startswith(mark) for mark in SUSPICIOUS_PATHS) or path == '/wp-login.php':
            flags.append('känslig sökväg')
            sensitive_by_ip[ip] += 1
        if status in (401, 403):
            flags.append('HTTP 401/403')
            denied_by_ip[ip] += 1
        if status == 429:
            flags.append('HTTP 429')
            limited_by_ip[ip] += 1
        if flags:
            hits[ip] += 1
            if len(examples) < 40:
                examples.append((ip, status, path[:180], ', '.join(flags)))
        stamp = re.search(r'\[([^]]+)\]', raw)
        if stamp:
            try:
                moment = datetime.strptime(stamp.group(1), '%d/%b/%Y:%H:%M:%S %z')
                moments[ip].append(moment)
            except ValueError:
                pass
    peaks = {}
    for ip, times in moments.items():
        times.sort()
        left, peak = 0, 0
        for right, moment in enumerate(times):
            while moment - times[left] >= timedelta(seconds=60):
                left += 1
            peak = max(peak, right - left + 1)
        peaks[ip] = peak
    return {'total_lines': len(content.splitlines()), 'parsed': parsed,
            'invalid': invalid, 'codes': codes, 'top_ips': ips.most_common(10),
            'suspicious': hits.most_common(15), 'examples': examples,
            'clients': clients, 'peaks': peaks,
            'sensitive_by_ip': sensitive_by_ip, 'denied_by_ip': denied_by_ip,
            'limited_by_ip': limited_by_ip}


def log_report(data, filename):
    lines = [f'RWB CYBERGUARD SWEDEN {VERSION} – INTRÅNGSINDIKATIONER',
             f'Analys: {dt.datetime.now().astimezone().isoformat(timespec="seconds")}',
             f'Importerad fil: {filename}',
             f'Tolkade förfrågningar: {data["parsed"]} av {data["total_lines"]} rader',
             'OBS: Misstänkta förfrågningar innebär inte ett bekräftat intrång.', '',
             'HTTP-STATUS']
    lines += [f'  {code}: {count}' for code,count in sorted(data['codes'].items())]
    lines += ['', 'KLIENTER (User-Agent kan förfalskas)']
    lines += [f'  {name}: {count}' for name, count in data['clients'].most_common()]
    lines += ['', 'HÖGSTA ANTAL FÖRFRÅGNINGAR UNDER 60 SEKUNDER (per IP)']
    lines += [f'  {ip}: {peak}' for ip, peak in sorted(data['peaks'].items(), key=lambda x: -x[1])[:10]]
    lines += [f'Otolkade rader (exklusive kommentarer): {data["invalid"]}',
              'OBS: Trafiktoppar, IP och User-Agent är indikationer, inte bevis på angrepp.']
    lines += ['', 'TRAFIKINDIKATORER PER IP – HEURISTISK PRIORITERING',
              'Poängen används enbart för manuell granskning, inte som bevis eller automatisk blockering.']
    for ip, count in data['top_ips']:
        sensitive = data['sensitive_by_ip'][ip]
        denied = data['denied_by_ip'][ip]
        limited = data['limited_by_ip'][ip]
        peak = data['peaks'].get(ip, 0)
        # Avsiktligt försiktiga, förklarbara regler; frekvens ensam räcker inte.
        score = min(100, min(sensitive, 10)*4 + min(denied, 10)*3 +
                    min(limited, 10)*4 + (15 if peak >= 60 else 0))
        level = 'Förhöjd granskning' if score >= 50 else ('Granska' if score >= 20 else 'Låg signalnivå')
        lines.append(f'  {ip}: {score}/100 – {level} | totalt {count}, känsliga {sensitive}, 401/403 {denied}, 429 {limited}, topp/60s {peak}')
    lines += ['OBS: Poängmodellen är experimentell och saknar kalibrering mot verkliga angrepp.']
    lines += ['', 'IP-ADRESSER MED INDIKATIONER (känsliga uppgifter – dela inte öppet)']
    lines += [f'  {ip}: {count}' for ip,count in data['suspicious']]
    lines += ['', 'EXEMPEL PÅ BEGÄRANDEN']
    lines += [f'  {ip} | HTTP {status} | {path} | {flag}'
              for ip,status,path,flag in data['examples']]
    if not data['parsed']:
        lines += ['Inga tolkbara Apache/Nginx accessloggrader hittades.']
    return '\n'.join(lines) + '\n'


def parse_kev_feed(payload):
    """Filtrerar CISA KEV; levererar inte bevis på att lokal webbplats påverkas."""
    data = json.loads(payload)
    items = data.get('vulnerabilities', [])
    if not isinstance(items, list):
        raise ValueError('Ogiltigt format i KEV-data')
    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fields = ' '.join(str(item.get(k,'')) for k in
                          ('vendorProject','product','vulnerabilityName','shortDescription')).lower()
        if re.search(r'\bphp\b|wordpress|woocommerce', fields):
            matches.append(item)
    matches.sort(key=lambda x: x.get('dateAdded',''), reverse=True)
    return matches[:50], len(items)


def kev_report(items, total):
    lines = [f'RWB CYBERGUARD SWEDEN {VERSION} – EARLY WARNING',
             f'Kontrollerad: {dt.datetime.now().astimezone().isoformat(timespec="seconds")}',
             'Källa: CISA Known Exploited Vulnerabilities (KEV)', KEV_URL,
             f'Totalt i flödet: {total}; relevanta PHP/WordPress-träffar: {len(items)}',
             'OBS: En träff innebär INTE att just din webbplats är sårbar.',
             'Matcha produkt, installerad version och leverantörens patchstatus.', '']
    for item in items:
        lines += [f'{item.get("cveID", "Okänt CVE")} | tillagd {item.get("dateAdded", "?")}',
                  f'  {item.get("vendorProject", "")} / {item.get("product", "")}',
                  f'  {item.get("vulnerabilityName", "")}',
                  f'  Åtgärd: {item.get("requiredAction", "Se leverantörens information")}', '']
    if not items:
        lines.append('Inga matchningar i denna filtrering; frånvaro betyder inte att risk saknas.')
    return '\n'.join(lines) + '\n'

# AI-utkast: endast valda aggregerade säkerhetsuppgifter, aldrig råa loggar.
AI_INTRO = ("Du är en defensiv cybersäkerhetsrådgivare. Analysera dessa uppgifter från "
            "RWB CyberGuard Sweden. Skilj konstaterade observationer från okända "
            "förhållanden. Prioritera vad som bör undersökas, förklara varför och "
            "ange säkra, praktiska frågor till webbhotell eller administratör. "
            "Påstå inte att intrång eller exploaterbarhet bekräftats. Ange vilka "
            "uppgifter som behöver verifieras och använd officiella källor.\n\n")


def ai_preview_data(kind, app):
    """Vitlista mätfält; aldrig kopiera fria loggrader, adresser eller HTTP-sökvägar."""
    lines = []
    if kind == 'web':
        if not app.current_report:
            raise ValueError('Kör webbplatskontrollen först.')
        lines.append('Typ: webbplatskontroll (passiv kontroll av svarshuvuden).')
        report = app.current_report
        # Endast fördefinierade rubriker/utfall; inga URL:er eller webbplatsnamn.
        for name in ('TLSv1.3', 'TLSv1.2'):
            if 'Giltig TLS-anslutning: '+name in report:
                lines.append('TLS-version: '+name)
                break
        for name in ('HSTS', 'CSP (aktiv)', 'X-Content-Type-Options', 'Referrer-Policy', 'Inbäddningsskydd'):
            if '✓ '+name+':' in report:
                lines.append(name+': identifierat (kvalitet ej verifierad)')
            elif '! '+name+':' in report:
                lines.append(name+': saknas eller identifierades inte')
            else:
                lines.append(name+': ej bedömt')
        if 'Certifikatet är utgånget.' in report:
            lines.append('Certifikat: utgånget enligt kontrollen')
        elif 'Certifikatet går ut inom 14 dagar' in report:
            lines.append('Certifikat: under 14 dagar kvar')
        elif 'Certifikatet går ut inom 30 dagar' in report:
            lines.append('Certifikat: under 30 dagar kvar')
        else:
            lines.append('Certifikat: ingen korttidsvarning noterad; kontrollera separat')
    elif kind == 'php':
        if not app.analyse_php():
            raise ValueError('PHP-analysen kunde inte genomföras.')
        lines.append('Typ: PHP versions- och konfigurationsanalys; samtliga värden manuellt angivna.')
        version = app.php_version.get().strip()
        if not re.fullmatch(r'\d+\.\d+\.\d+', version):
            raise ValueError('PHP-versionens format är ogiltigt.')
        lines.append('PHP-version (ej serververifierad): '+version)
        versions = {'yes': 'ja', 'no': 'nej', 'unknown': 'okänt'}
        handlers = {'php':'php','php_binary':'php_binary','php_serialize':'php_serialize','other':'annan','unknown':'okänt'}
        lines.append('session.upload_progress.enabled: '+versions[app.session_upload.get()])
        lines.append('session.serialize_handler: '+handlers[app.session_handler.get()])
        lines.append('Runtime-byte till php före session_start: '+versions[app.session_switch.get()])
        lines.append('Riskstatus: '+('oklart / ej verifierat' if 'OKLART:' in app.php_analysis else 'kräver manuell verifiering av rapporten'))
    elif kind == 'log':
        d = app.log_summary
        if not d:
            raise ValueError('Importera och analysera en logg först.')
        lines.append('Typ: sammanfattad logganalys utan IP-adresser, User-Agent-strängar och sökvägar.')
        lines.append('Tolkade förfrågningar: '+str(d['parsed']))
        lines.append('Otolkade rader: '+str(d['invalid']))
        for code, count in sorted(d['codes'].items()):
            lines.append(f'HTTP {int(code)}: {int(count)}')
        lines.append('Antal klienter med sökvägsindikatorer: '+str(len(d['suspicious'])))
        lines.append('Indikatorer är inte bevis på intrång.')
    elif kind == 'warning':
        if not app.warning_report_data:
            raise ValueError('Hämta eller importera säkerhetsvarningar först.')
        demo = 'DEMONSTRATION' in app.warning_report_data
        lines.append('Typ: '+('SYNTETISK DEMODATA (INTE VERKLIGA CVE-UPPGIFTER)' if demo else 'CISA KEV-varningar (produktmatchning ej verifierad).'))
        for item in app.warning_items[:15]:
            cve = str(item.get('cveID',''))
            if re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
                lines.append('Listat CVE: '+cve)
        lines.append('Verifiera alltid faktisk produkt, version, patchnivå och leverantör.')
    else:
        raise ValueError('Okänd analyskälla.')
    return AI_INTRO + '\n'.join(lines) + '\n\nSvara på svenska med högst fem prioriterade kontroller och förslag till nästa steg.\n'


class CyberGuardApp:
    def __init__(self, root):
        self.root = root
        root.title(f"RWB CyberGuard Sweden {VERSION}")
        # Ikon från programmets installationsmapp, om Pillow-fri PNG stöds av Tk.
        # Bildreferensen behålls för att Tk inte ska frigöra bilden.
        try:
            icon_file = Path.home() / "RWB-CyberGuard" / "Ikoner" / "rwb_cyberguard_icon_256.png"
            if icon_file.is_file():
                self.app_icon = tk.PhotoImage(file=str(icon_file))
                root.iconphoto(True, self.app_icon)
        except (tk.TclError, OSError):
            self.app_icon = None
        root.geometry("1180x800")
        root.minsize(960, 620)
        self.results = queue.Queue()
        self.current_report = ""
        self.current_advice = ""
        outer = ttk.Frame(root, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="RWB CyberGuard Sweden", font=("Arial", 20, "bold")).pack()
        ttk.Label(outer, text=f"Webbplatssäkerhet • RWB Tech Lab • Version {VERSION}").pack(pady=(3, 9))
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        web = ttk.Frame(self.notebook, padding=10)
        self.php_tab = ttk.Frame(self.notebook, padding=8)
        advice_tab = ttk.Frame(self.notebook, padding=10)
        hist_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(web, text="Webbplatskontroll")
        self.notebook.add(self.php_tab, text="PHP Security Inspector")
        self.notebook.add(advice_tab, text="Security Advisor")
        self.notebook.add(hist_tab, text="Historik och export")
        logs_tab = ttk.Frame(self.notebook, padding=10)
        warning_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(logs_tab, text="Intrångsanalys")
        self.notebook.add(warning_tab, text="Tidiga varningar")

        ttk.Label(web, text="Välj registrerad webbplats (endast egen eller med tillstånd):").pack(anchor="w")
        self.sites = []
        self.selected_site = None
        self.site_choice = tk.StringVar()
        self.website = ttk.Combobox(web, textvariable=self.site_choice, state="readonly", font=("Arial", 11))
        self.website.pack(fill="x", pady=(3, 3))
        self.website.bind("<<ComboboxSelected>>", self.select_site)
        HoverTip(self.website, lambda: self.selected_site["url"] if self.selected_site else "")
        ttk.Label(web, text="Fullständig adress (endast läsning):").pack(anchor="w")
        self.full_url = tk.StringVar()
        ttk.Entry(web, textvariable=self.full_url, state="readonly").pack(fill="x", pady=(2, 6))
        sitebar = ttk.Frame(web)
        sitebar.pack(fill="x", pady=(0, 3))
        ttk.Button(sitebar, text="Hantera webbplatser", command=self.manage_sites).pack(side="left")
        self.site_status = ttk.Label(sitebar, text="Ingen webbplats vald.")
        self.site_status.pack(side="left", padx=12)
        ttk.Label(web, text="'Bevakning aktiv' är en sparad markering, inte automatisk övervakning.").pack(anchor="w")
        self.init_sites()
        ttk.Label(web, text="Undersidor (kommaseparerade, högst fyra):").pack(anchor="w")
        self.paths = ttk.Entry(web)
        self.paths.pack(fill="x", pady=(3, 7))
        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(web, text="Jag äger webbplatsen eller har tillstånd att kontrollera den.", variable=self.authorized).pack(anchor="w", pady=(0, 7))
        controls = ttk.Frame(web)
        controls.pack(anchor="w", pady=4)
        self.start_btn = ttk.Button(controls, text="Starta säkerhetskontroll", command=self.start)
        self.start_btn.pack(side="left", padx=3)
        self.save_btn = ttk.Button(controls, text="Spara rapport (.txt)", command=self.save, state="disabled")
        self.save_btn.pack(side="left", padx=3)
        self.report_xlsx_btn = ttk.Button(controls, text="Rapport till Excel", command=self.export_report, state="disabled")
        self.report_xlsx_btn.pack(side="left", padx=3)
        ttk.Button(controls, text="Analysera med ChatGPT", command=lambda: self.preview_ai("web")).pack(side="left", padx=3)
        self.status = ttk.Label(web, text="Redo att starta.")
        self.status.pack(pady=4)
        ttk.Label(web, text="Säkerhetsrapport", font=("Arial", 12, "bold")).pack(anchor="w")
        self.output = scrolledtext.ScrolledText(web, font=("DejaVu Sans Mono", 10), wrap="word")
        self.output.pack(fill="both", expand=True, pady=(5, 4))
        self.output.configure(state="disabled")
        ttk.Label(web, text="Passiv kontroll • HTTPS • Högst fem sidor • Endast tillåtna webbplatser").pack()

        self.advisor_btn = ttk.Button(advice_tab, text="Visa senaste råd", command=self.show_advisor, state="disabled")
        self.advisor_btn.pack(anchor="w", pady=(0, 8))
        ttk.Button(advice_tab, text="Analysera med ChatGPT", command=lambda: self.preview_ai("web")).pack(anchor="w", pady=(0, 8))
        self.advice_output = scrolledtext.ScrolledText(advice_tab, wrap="word", font=("DejaVu Sans Mono", 10))
        self.advice_output.pack(fill="both", expand=True)
        self.advice_output.insert("1.0", "Kör en webbplatskontroll för att få svenska rekommendationer.")
        self.advice_output.configure(state="disabled")

        h_buttons = ttk.Frame(hist_tab)
        h_buttons.pack(anchor="w", pady=(0, 8))
        ttk.Button(h_buttons, text="Visa diagram och jämförelser", command=self.show_history).pack(side="left", padx=4)
        ttk.Button(h_buttons, text="Exportera historik till Excel + CSV", command=self.export_history).pack(side="left", padx=4)
        ttk.Button(h_buttons, text="Uppdatera lista", command=self.refresh_history_tab).pack(side="left", padx=4)
        self.history_table = ttk.Treeview(hist_tab, columns=("tid", "domän", "sidor", "skydd", "granska"), show="headings", height=17)
        for key, name, width in (("tid","Tidpunkt",190),("domän","Domän",230),("sidor","Sidor",70),("skydd","Skydd",85),("granska","Att granska",100)):
            self.history_table.heading(key, text=name)
            self.history_table.column(key, width=width, anchor="w")
        self.history_table.pack(fill="both", expand=True)
        ttk.Label(hist_tab, text="Antalen är kontroller per sida, inte en säkerhetspoäng.").pack(anchor="w", pady=6)
        self.create_php_tab()
        self.create_logs_tab(logs_tab)
        self.create_warning_tab(warning_tab)
        self.refresh_history_tab()
        self.closing = False
        self.poll_job = self.root.after(100, self.poll)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def init_sites(self):
        try:
            self.sites = load_websites()
        except (OSError, ValueError, TypeError) as exc:
            self.sites = []
            messagebox.showerror("Webbadresser", f"Webbplatslistan kunde inte läsas. Ingen fil har ändrats.\n\n{exc}")
            self.site_storage_error = True
        else:
            self.site_storage_error = False
        self.refresh_sites()

    def refresh_sites(self, selected_url=None):
        previous = selected_url or (self.selected_site["url"] if self.selected_site else None)
        labels = [f'{site["namn"]} — {short_url(site["url"])}' for site in self.sites]
        self.website.configure(values=labels)
        index = next((i for i, item in enumerate(self.sites) if item["url"] == previous),
                     0 if self.sites else -1)
        if index >= 0:
            self.website.current(index)
            self.selected_site = self.sites[index]
            self.full_url.set(self.selected_site["url"])
            self.site_status.configure(text="Bevakning aktiv (manuell kontroll)" if self.selected_site["bevakning"] else "Bevakning ej markerad")
        else:
            self.website.set("")
            self.selected_site = None
            self.full_url.set("")
            self.site_status.configure(text="Ingen webbplats registrerad")

    def select_site(self, event=None):
        index = self.website.current()
        if 0 <= index < len(self.sites):
            self.selected_site = self.sites[index]
            self.full_url.set(self.selected_site["url"])
            self.site_status.configure(text="Bevakning aktiv (manuell kontroll)" if self.selected_site["bevakning"] else "Bevakning ej markerad")
        else:
            self.selected_site = None
            self.full_url.set("")

    def persist_sites(self, new_sites, selected_url=None):
        try:
            save_websites(new_sites)
        except OSError as exc:
            messagebox.showerror("Webbadresser", f"Kunde inte spara webbplatslistan:\n{exc}")
            return False
        self.sites = new_sites
        self.site_storage_error = False
        self.refresh_sites(selected_url)
        return True

    def site_dialog(self, initial=None):
        dialog = tk.Toplevel(self.root, class_="RWB-CyberGuard-Alpha6")
        dialog.title("Redigera webbplats" if initial else "Lägg till webbplats")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        panel = ttk.Frame(dialog, padding=16)
        panel.pack(fill="both", expand=True)
        name = tk.StringVar(value=initial["namn"] if initial else "")
        url = tk.StringVar(value=initial["url"] if initial else "https://")
        ttk.Label(panel, text="Namn:").pack(anchor="w")
        e_name = ttk.Entry(panel, textvariable=name, width=70)
        e_name.pack(fill="x", pady=(2, 10))
        ttk.Label(panel, text="Fullständig HTTPS-adress:").pack(anchor="w")
        ttk.Entry(panel, textvariable=url, width=70).pack(fill="x", pady=(2, 10))
        ttk.Label(panel, text="Kontrollnivå 1: manuella, passiva kontroller").pack(anchor="w")
        result = [None]
        def accept():
            try:
                n, u = validate_website(name.get(), url.get())
                if any(s["url"] == u and (initial is None or s["url"] != initial["url"]) for s in self.sites):
                    raise ValueError("Webbadressen är redan registrerad.")
            except (ValueError, TypeError) as exc:
                messagebox.showerror("Felaktig webbadress", str(exc), parent=dialog)
                return
            result[0] = {"namn": n, "url": u,
                         "bevakning": initial["bevakning"] if initial else False,
                         "kontrollniva": 1}
            dialog.destroy()
        bar = ttk.Frame(panel)
        bar.pack(anchor="e", pady=(14, 0))
        ttk.Button(bar, text="Avbryt", command=dialog.destroy).pack(side="left", padx=4)
        ttk.Button(bar, text="Spara", command=accept).pack(side="left", padx=4)
        dialog.bind("<Escape>", lambda event: dialog.destroy())
        e_name.focus_set()
        self.root.wait_window(dialog)
        return result[0]

    def manage_sites(self):
        if getattr(self, "site_storage_error", False):
            messagebox.showerror("Webbadresser", "Listan innehåller ett läsfel. Skydda och rätta JSON-filen innan du gör ändringar.")
            return
        win = tk.Toplevel(self.root, class_="RWB-CyberGuard-Alpha6")
        win.title("RWB CyberGuard – Registrerade webbplatser")
        win.geometry("950x480")
        win.minsize(690, 370)
        win.transient(self.root)
        container = ttk.Frame(win, padding=12)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text="Registrerade webbplatser", font=("Arial", 15, "bold")).pack(anchor="w")
        ttk.Label(container, text="Klicka i första kolumnen för att växla bevakning. Markeringen utför INGA automatiska kontroller.").pack(anchor="w", pady=(4, 9))
        cols = ("enabled", "name", "url", "level")
        tree = ttk.Treeview(container, columns=cols, show="headings", selectmode="browse")
        for key, title, width in (("enabled", "Bevakning", 90), ("name", "Namn", 180),
                                  ("url", "Adress (förkortad)", 480), ("level", "Nivå", 60)):
            tree.heading(key, text=title)
            tree.column(key, width=width, stretch=key == "url")
        tree.pack(fill="both", expand=True)
        full = tk.StringVar()
        ttk.Label(container, text="Fullständig adress:").pack(anchor="w", pady=(8, 2))
        ttk.Entry(container, textvariable=full, state="readonly").pack(fill="x")
        def current_index():
            items = tree.selection()
            return int(items[0]) if items else None
        def update_full(event=None):
            i = current_index()
            full.set(self.sites[i]["url"] if i is not None and i < len(self.sites) else "")
        def redraw(select=None):
            for row in tree.get_children():
                tree.delete(row)
            for i, item in enumerate(self.sites):
                tree.insert("", "end", iid=str(i), values=("☑" if item["bevakning"] else "☐",
                            item["namn"], short_url(item["url"], 65), item["kontrollniva"]))
            if self.sites:
                i = min(select if select is not None else 0, len(self.sites)-1)
                tree.selection_set(str(i))
            update_full()
        def toggle(index=None):
            i = current_index() if index is None else index
            if i is None:
                return
            sites = [dict(s) for s in self.sites]
            sites[i]["bevakning"] = not sites[i]["bevakning"]
            if self.persist_sites(sites):
                redraw(i)
        def click(event):
            if tree.identify_region(event.x, event.y) == "cell" and tree.identify_column(event.x) == "#1":
                item = tree.identify_row(event.y)
                if item:
                    tree.selection_set(item)
                    toggle(int(item))
                    return "break"
        tree.bind("<Button-1>", click, add="+")
        tree.bind("<<TreeviewSelect>>", update_full)
        def add():
            item = self.site_dialog()
            if item and self.persist_sites(self.sites + [item], item["url"]):
                redraw(len(self.sites)-1)
        def edit():
            i = current_index()
            if i is None:
                return
            item = self.site_dialog(self.sites[i])
            if item:
                sites = [dict(s) for s in self.sites]
                sites[i] = item
                if self.persist_sites(sites, item["url"]):
                    redraw(i)
        def remove():
            i = current_index()
            if i is None:
                return
            if not messagebox.askyesno("Ta bort webbplats", f'Ta bort {self.sites[i]["namn"]} från listan?\n\nSparad historik och rapporter påverkas inte.', parent=win):
                return
            sites = [dict(s) for j, s in enumerate(self.sites) if j != i]
            if self.persist_sites(sites):
                redraw(min(i, len(self.sites)-1))
        bar = ttk.Frame(container)
        bar.pack(fill="x", pady=(12, 0))
        for name, callback in (("Lägg till", add), ("Redigera", edit), ("Ta bort", remove), ("Växla bevakning", toggle)):
            ttk.Button(bar, text=name, command=callback).pack(side="left", padx=(0, 7))
        ttk.Button(bar, text="Stäng", command=win.destroy).pack(side="right")
        redraw()

    def create_logs_tab(self, parent):
        ttk.Label(parent, text="Lokal analys av accessloggar", font=("Arial", 16, "bold")).pack(anchor="w")
        ttk.Label(parent, text="Importera egen Apache/Nginx access.log. Programmet skickar inte loggar någonstans.").pack(anchor="w", pady=7)
        bar = ttk.Frame(parent)
        bar.pack(anchor="w", pady=6)
        ttk.Button(bar, text="Importera och analysera logg", command=self.load_log).pack(side="left", padx=3)
        ttk.Button(bar, text="Spara loggrapport TXT", command=lambda: self.save_extra_report('log')).pack(side="left", padx=3)
        ttk.Button(bar, text="Exportera logganalys XLSX", command=lambda: self.export_extra_excel('log')).pack(side="left", padx=3)
        ttk.Button(bar, text="Analysera med ChatGPT", command=lambda: self.preview_ai("log")).pack(side="left", padx=3)
        self.log_text = scrolledtext.ScrolledText(parent, wrap="word", font=("DejaVu Sans Mono", 10))
        self.log_text.pack(fill="both", expand=True)
        self.log_text.insert("1.0", "Ingen logg analyserad. Stöd för Apache/Nginx common/combined-format.\nLoggar kan innehålla personuppgifter; förvara rapporter skyddat.")
        self.log_report_data = ''
        self.log_summary = None

    def load_log(self):
        path = filedialog.askopenfilename(title="Välj en accesslogg", filetypes=[("Loggfiler", "*.log *.txt"), ("Alla filer", "*")])
        if not path:
            return
        try:
            if Path(path).stat().st_size > MAX_LOG_BYTES:
                raise ValueError("Filen är större än 12 MB. Dela loggfilen i mindre delar först.")
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            self.log_summary = analyse_access_log(content)
            self.log_report_data = log_report(self.log_summary, Path(path).name)
            self.log_text.delete("1.0", "end")
            self.log_text.insert("1.0", self.log_report_data)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Logganalys", str(exc))

    def create_warning_tab(self, parent):
        ttk.Label(parent, text="Early Warning – officiella säkerhetsvarningar", font=("Arial", 16, "bold")).pack(anchor="w")
        ttk.Label(parent, text="Hämtar CISA:s KEV-lista på begäran. Ingen automatisk anslutning eller skanning.").pack(anchor="w", pady=6)
        bar = ttk.Frame(parent)
        bar.pack(anchor="w", pady=6)
        self.fetch_btn = ttk.Button(bar, text="Hämta CISA KEV", command=self.fetch_warnings)
        self.fetch_btn.pack(side="left", padx=3)
        ttk.Button(bar, text="Importera KEV-demo (JSON)", command=self.import_demo_kev).pack(side="left", padx=3)
        ttk.Button(bar, text="Spara varningar TXT", command=lambda: self.save_extra_report('warning')).pack(side="left", padx=3)
        ttk.Button(bar, text="Exportera varningar XLSX", command=lambda: self.export_extra_excel('warning')).pack(side="left", padx=3)
        ttk.Button(bar, text="Analysera med ChatGPT", command=lambda: self.preview_ai("warning")).pack(side="left", padx=3)
        self.warning_text = scrolledtext.ScrolledText(parent, wrap="word", font=("DejaVu Sans Mono", 10))
        self.warning_text.pack(fill="both", expand=True)
        self.warning_text.insert("1.0", "Klicka på Hämta CISA KEV. En träff betyder inte att webbplatsen är sårbar.\nKontrollera alltid installerad version och webbhotellets rättningar.")
        self.warning_report_data = ''
        self.warning_items = []

    def import_demo_kev(self):
        path = filedialog.askopenfilename(
            title="Välj syntetisk KEV-demofil (JSON)",
            filetypes=[("JSON-filer", "*.json"), ("Alla filer", "*")])
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                payload = handle.read(MAX_FEED_BYTES + 1)
            if len(payload) > MAX_FEED_BYTES:
                raise ValueError("Filen är för stor (över 8 MB).")
            data = json.loads(payload)
            if not isinstance(data, dict) or not str(data.get("catalogVersion", "")).startswith("DEMO-") or "_demo_notice" not in data:
                raise ValueError("Endast tydligt märkta syntetiska demofiler accepteras av den här knappen.")
            items, total = parse_kev_feed(payload)
            report = ("*** DEMONSTRATION – PÅHITTADE UPPGIFTER, INTE CISA-VARNINGAR ***\n"
                      "Källa: lokal syntetisk testfil. Inga data hämtades från CISA.\n\n" +
                      kev_report(items, total).replace("Källa: CISA Known Exploited Vulnerabilities (KEV)",
                      "Källa: RWB CyberGuard lokal DEMOFIL (inte CISA)").replace(KEV_URL,"Lokal demofil"))
            self.warning_items = items
            self.warning_report_data = report
            self.warning_text.delete("1.0", "end")
            self.warning_text.insert("1.0", report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("Demofil", f"JSON-filen kunde inte importeras. Den tidigare rapporten har inte ändrats.\n\nTekniska detaljer: {exc}")

    def fetch_warnings(self):
        self.fetch_btn.configure(state="disabled")
        self.warning_text.delete("1.0", "end")
        self.warning_text.insert("1.0", "Hämtar officiell KEV-data …")
        def job():
            try:
                req = Request(KEV_URL, headers={'User-Agent': 'RWB-CyberGuard/3.0-Alpha6'})
                with urlopen(req, timeout=12) as response:
                    payload = response.read(MAX_FEED_BYTES+1)
                if len(payload) > MAX_FEED_BYTES:
                    raise ValueError('Säkerhetsflödet överstiger 8 MB')
                items, total = parse_kev_feed(payload)
                self.results.put(('kev', items, kev_report(items, total), None))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.results.put(('kev', [], '', str(exc)))
        threading.Thread(target=job, daemon=True).start()

    def save_extra_report(self, kind):
        report = self.log_report_data if kind == 'log' else self.warning_report_data
        if not report:
            messagebox.showinfo("Ingen rapport", "Genomför först en analys.")
            return
        try:
            create_export_dirs()
            path = dated_name('CyberGuard_Logganalys' if kind == 'log' else 'CyberGuard_EarlyWarning', 'txt')
            path.write_text(report, encoding='utf-8')
            messagebox.showinfo("Sparat", str(path))
        except OSError as exc:
            messagebox.showerror("Fel vid sparning", str(exc))

    def export_extra_excel(self, kind):
        report = self.log_report_data if kind == 'log' else self.warning_report_data
        if not report:
            messagebox.showinfo("Ingen rapport", "Genomför först en analys.")
            return
        rows = [["Rad", "Rapporttext"]] + [[i, line] for i, line in enumerate(report.splitlines(), 1)]
        sheets = [('Rapporttext', rows)]
        if kind == 'log' and self.log_summary:
            d = self.log_summary
            sheets.insert(0, ('HTTP-status', [['HTTP-status','Antal']] + [[a,b] for a,b in sorted(d['codes'].items())]))
            sheets.insert(1, ('Indikationer', [['IP-adress','HTTP-status','Sökväg','Indikation']] + [list(x) for x in d['examples']]))
            risk_rows = [['IP-adress','Förfrågningar','Känsliga','HTTP 401/403','HTTP 429','Topp per 60 s','Prioritetspoäng','Bedömning']]
            for ip, count in d['top_ips']:
                sensitive = d['sensitive_by_ip'][ip]
                denied = d['denied_by_ip'][ip]
                limited = d['limited_by_ip'][ip]
                peak = d['peaks'].get(ip, 0)
                score = min(100, min(sensitive, 10)*4 + min(denied, 10)*3 + min(limited, 10)*4 + (15 if peak >= 60 else 0))
                level = 'Förhöjd granskning' if score >= 50 else ('Granska' if score >= 20 else 'Låg signalnivå')
                risk_rows.append([ip,count,sensitive,denied,limited,peak,score,level])
            sheets.insert(2, ('Riskpoäng per IP', risk_rows))
        if kind == 'warning':
            sheets.insert(0, ('CISA KEV', [['CVE','Datum','Leverantör','Produkt','Beskrivning','Rekommenderad åtgärd']] +
                          [[item.get('cveID',''),item.get('dateAdded',''),item.get('vendorProject',''),
                            item.get('product',''),item.get('vulnerabilityName',''),item.get('requiredAction','')] for item in self.warning_items]))
        try:
            create_export_dirs()
            path = dated_name('CyberGuard_Logganalys' if kind == 'log' else 'CyberGuard_EarlyWarning','xlsx')
            write_workbook_xlsx(path, sheets)
            messagebox.showinfo("Excel-export sparad", str(path))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Excel-export", str(exc))

    def refresh_history_tab(self):
        for row in self.history_table.get_children():
            self.history_table.delete(row)
        for record in history_load():
            if isinstance(record, dict):
                pages, good, missing = history_summary(record)
                self.history_table.insert("", "end", values=(swedish_time(record.get("time", "")), record.get("host", ""), pages, good, missing))

    def display(self, text):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", text)
        self.output.configure(state="disabled")

    def start(self):
        if not self.authorized.get():
            messagebox.showwarning("Tillstånd krävs", "Bekräfta att du har rätt att kontrollera webbplatsen.")
            return
        try:
            url = normalize_url(self.selected_site["url"] if self.selected_site else "")
            paths = [part.strip() for part in self.paths.get().split(",") if part.strip()]
            if len(paths) > MAX_PAGES - 1:
                raise ValueError("Ange högst fyra extra undersidor.")
        except ValueError as exc:
            messagebox.showerror("Felaktig inmatning", str(exc))
            return
        self.current_report = ""
        self.current_advice = ""
        self.advisor_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.report_xlsx_btn.configure(state="disabled")
        self.start_btn.configure(state="disabled")
        self.display("Kontrollerar webbplatsen …")
        self.status.configure(text="Kontroll pågår …")
        threading.Thread(target=self.worker, args=(url, paths), daemon=True).start()

    def worker(self, url, paths):
        try:
            result = check_site(url, paths)
        except Exception as exc:
            result = f"Kontrollen kunde inte genomföras:\n{type(exc).__name__}: {exc}"
        self.results.put(result)

    def on_close(self):
        self.closing = True

        if self.poll_job is not None:
            try:
                self.root.after_cancel(self.poll_job)
            except tk.TclError:
                pass
            self.poll_job = None

        self.root.destroy()


    def poll(self):
        if self.closing:
          return

        self.poll_job = None

        try:
            result = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            if isinstance(result, tuple) and result[0] == 'kev':
                _, items, report, err = result
                self.fetch_btn.configure(state="normal")
                if err:
                    self.warning_text.delete("1.0", "end")
                    self.warning_text.insert("1.0", "Kunde inte hämta CISA KEV: " + err + "\nIngen ny data har verifierats.")
                else:
                    self.warning_items = items
                    self.warning_report_data = report
                    self.warning_text.delete("1.0", "end")
                    self.warning_text.insert("1.0", report)
                    self.poll_job = self.root.after(100, self.poll)
                return
            self.current_report = result
            if "RWB SECURITY ADVISOR" in result:
                self.current_advice = "RWB SECURITY ADVISOR" + result.split("RWB SECURITY ADVISOR", 1)[1].split("\nKontrollen avslutad.", 1)[0].rstrip()
                self.advisor_btn.configure(state="normal")
                self.advice_output.configure(state="normal")
                self.advice_output.delete("1.0", "end")
                self.advice_output.insert("1.0", self.current_advice)
                self.advice_output.configure(state="disabled")
            self.display(result)
            self.start_btn.configure(state="normal")
            self.save_btn.configure(state="normal")
            self.report_xlsx_btn.configure(state="normal")
            self.status.configure(text="Kontroll avslutad.")
            self.refresh_history_tab()
            try:
                path = save_dated_report(result)
                self.status.configure(text=f"Rapport sparad: {path.name}")
            except OSError as exc:
                messagebox.showwarning("Rapport", f"Automatisk rapport kunde inte sparas: {exc}")
        self.poll_job = self.root.after(100, self.poll)

    def preview_ai(self, kind):
        """Förhandsgranska/redigera; endast användarinitierad kopiering, ingen API-överföring."""
        try:
            content = ai_preview_data(kind, self)
        except (ValueError, KeyError) as exc:
            messagebox.showinfo('AI-analys', str(exc))
            return

        win = tk.Toplevel(
            self.root,
            class_="RWB-CyberGuard-Alpha6"
        )
        win.title('RWB CyberGuard – granska text före ChatGPT')
        win.geometry('880x690')
        win.minsize(630, 420)
        win.transient(self.root)
        ttk.Label(win, text='GRANSKA OCH REDIGERA innan du själv delar uppgifterna.',
                  font=('Arial', 12, 'bold')).pack(anchor='w', padx=12, pady=(12, 4))
        ttk.Label(win, text='Endast valda sammanfattningsfält har hämtats. Kontrollera ändå att inget känsligt finns kvar.',
                  wraplength=830).pack(anchor='w', padx=12)
        area = scrolledtext.ScrolledText(win, wrap='word', font=('DejaVu Sans Mono', 10))
        area.pack(fill='both', expand=True, padx=12, pady=9)
        area.insert('1.0', content)
        status = ttk.Label(win, text='Ingen information har skickats till ChatGPT.')
        status.pack(anchor='w', padx=12)
        bar = ttk.Frame(win)
        bar.pack(anchor='e', padx=12, pady=12)

        def copy_selected():
            selected = area.get('1.0', 'end-1c')
            if not selected.strip():
                messagebox.showwarning('Tom text', 'Skriv eller behåll analysunderlaget först.', parent=win)
                return
            if not messagebox.askyesno('Bekräfta kopiering',
                    'Har du granskat texten och tagit bort uppgifter du inte vill dela?\n\n'
                    'Texten kopieras endast till datorns urklipp. Ingen automatisk överföring sker.', parent=win):
                return
            win.clipboard_clear()
            win.clipboard_append(selected)
            win.update()
            status.configure(text='Text kopierad. Öppna ChatGPT och klistra in manuellt med Ctrl+V.')

        def open_chat():
            webbrowser.open('https://chatgpt.com/')
            status.configure(text='ChatGPT öppnas i webbläsaren. Klistra själv in texten när du vill.')

        ttk.Button(bar, text='Kopiera granskad text', command=copy_selected).pack(side='left', padx=4)
        ttk.Button(bar, text='Öppna ChatGPT', command=open_chat).pack(side='left', padx=4)
        ttk.Button(bar, text='Stäng', command=win.destroy).pack(side='left', padx=4)

    def show_advisor(self):
        if not self.current_advice:
            messagebox.showinfo("Security Advisor", "Genomför först en säkerhetskontroll.")
            return
        window = tk.Toplevel(
            self.root,
            class_="RWB-CyberGuard-Alpha6"
        )
        window.title(f"RWB Security Advisor – {VERSION}")
        window.geometry("830x550")
        window.transient(self.root)
        window.lift()
        window.focus_set()
        text = scrolledtext.ScrolledText(window, wrap="word", font=("DejaVu Sans Mono", 10))
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("1.0", self.current_advice)
        text.configure(state="disabled")

    def show_php_inspector(self):
        self.notebook.select(self.php_tab)

    def create_php_tab(self):
        parent = self.php_tab
        ttk.Label(parent, text="PHP Security Inspector", font=("Arial", 16, "bold")).pack(anchor="w")
        ttk.Label(parent, text="PHP-version: WordPress → Verktyg → Webbplatshälsa → Information → Server").pack(anchor="w", pady=3)
        self.php_version = ttk.Entry(parent, font=("Arial", 11))
        self.php_version.pack(fill="x", pady=3)
        self.php_patched = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Webbhotellet uppger särskilda säkerhetsrättningar (ej verifierat)", variable=self.php_patched).pack(anchor="w")
        settings = ttk.LabelFrame(parent, text="PHP Session Configuration Advisor – manuellt verifierade uppgifter", padding=7)
        settings.pack(fill="x", pady=5)
        self.session_upload = tk.StringVar(value="unknown")
        self.session_handler = tk.StringVar(value="unknown")
        self.session_switch = tk.StringVar(value="unknown")
        selectors = (
            ("session.upload_progress.enabled", self.session_upload,
             (("Okänt", "unknown"), ("Aktiverat (1)", "yes"), ("Avstängt (0)", "no"))),
            ("session.serialize_handler – grundinställning", self.session_handler,
             (("Okänt", "unknown"), ("php", "php"), ("php_binary", "php_binary"), ("php_serialize", "php_serialize"), ("Annat", "other"))),
            ("Byter appen till 'php' före session_start()?", self.session_switch,
             (("Okänt", "unknown"), ("Ja", "yes"), ("Nej", "no"))),
        )
        for label, var, options in selectors:
            line = ttk.Frame(settings)
            line.pack(fill="x", pady=2)
            ttk.Label(line, text=label, width=49, anchor="w").pack(side="left")
            combo = ttk.Combobox(line, state="readonly", width=25,
                                 values=[name for name, _ in options])
            # Visningsvärde konverteras till interna stabila värden via en uppslagstabell.
            lookup = dict(options)
            inverse = {v: k for k, v in options}
            combo.set(inverse[var.get()])
            combo.bind("<<ComboboxSelected>>", lambda event, v=var, c=combo, mapping=lookup: v.set(mapping[c.get()]))
            combo.pack(side="left", padx=4)
        ttk.Label(settings, text="Okänt är förvalt. Webbhotellets uppgifter krävs; ingen fjärravläsning görs.").pack(anchor="w", pady=(4, 0))
        self.php_analysis = ""
        controls = ttk.Frame(parent)
        controls.pack(anchor="w", pady=6)
        ttk.Button(controls, text="Analysera PHP + session", command=self.analyse_php).pack(side="left", padx=3)
        ttk.Button(controls, text="Spara PHP (.txt)", command=self.save_php).pack(side="left", padx=3)
        ttk.Button(controls, text="PHP till Excel (.xlsx)", command=self.export_php_excel).pack(side="left", padx=3)
        ttk.Button(controls, text="Lägg till i webbplatsrapport", command=self.append_php_report).pack(side="left", padx=3)
        ttk.Button(controls, text="Analysera med ChatGPT", command=lambda: self.preview_ai("php")).pack(side="left", padx=3)
        self.php_output = scrolledtext.ScrolledText(parent, wrap="word", font=("DejaVu Sans Mono", 10))
        self.php_output.pack(fill="both", expand=True)

    def analyse_php(self):
        try:
            self.php_analysis = (inspect_php_version(self.php_version.get(), self.php_patched.get())
                                 + inspect_php_session(self.session_upload.get(), self.session_handler.get(),
                                                       self.session_switch.get()))
        except ValueError as exc:
            self.php_analysis = ""
            self.php_output.delete("1.0", "end")
            self.php_output.insert("1.0", "INGEN AKTUELL PHP-ANALYS.\n" + str(exc) + "\nTidigare sparade rapporter har inte ändrats.")
            messagebox.showwarning("PHP-version", str(exc))
            return False
        self.php_output.delete("1.0", "end")
        self.php_output.insert("1.0", self.php_analysis)
        return True

    def save_php(self):
        if not self.analyse_php():
            return
        try:
            create_export_dirs()
            path = dated_name("CyberGuard_PHP_Rapport", "txt")
            path.write_text(self.php_analysis.rstrip() + "\n", encoding="utf-8")
            messagebox.showinfo("PHP-rapport sparad", str(path))
        except OSError as exc:
            messagebox.showerror("Kunde inte spara", str(exc))

    def export_php_excel(self):
        if not self.analyse_php():
            return
        try:
            path = export_php_xlsx(self.php_analysis, self.php_version.get(), self.php_patched.get())
            messagebox.showinfo("PHP till Excel", f"Excel-rapport skapad:\n{path}")
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Excel-exportfel", str(exc))

    def append_php_report(self):
        if not self.analyse_php():
            return
        if not self.current_report:
            messagebox.showinfo("Ingen webbplatsrapport", "Kör först en webbplatskontroll.")
            return
        marker = "\n\nRWB PHP SECURITY INSPECTOR – version "
        self.current_report = self.current_report.split(marker)[0] + marker + VERSION + "\n" + self.php_analysis.split("\n", 1)[-1]
        self.display(self.current_report)
        messagebox.showinfo("Tillagd", "PHP-analysen har lagts till i den aktuella rapporten.")

    def export_report(self):
        if not self.current_report:
            messagebox.showinfo("Rapport till Excel", "Gör först en säkerhetskontroll.")
            return
        try:
            path = write_report_xlsx(self.current_report)
            messagebox.showinfo("Excel-rapport skapad",
                                f"Rapporten sparades här:\n{path}\n\n"
                                "Blad: Sammanfattning, Kontroller, Rådgivare och Rapporttext.")
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Exportfel", str(exc))

    def export_history(self):
        records = history_load()
        if not records:
            messagebox.showinfo("Exportera historik", "Ingen historik har sparats ännu.")
            return
        try:
            xlsx = write_xlsx_export(records)
            csv_paths = write_csv_exports(records)
            backup = backup_history()
            messagebox.showinfo("Historik exporterad", "XLSX: " + str(xlsx) +
                                "\n\nCSV-filer: " + "\n".join(str(p) for p in csv_paths) +
                                ("\n\nSäkerhetskopia: " + str(backup) if backup else ""))
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Exportfel", str(exc))

    def show_history(self):
        """Lokal historiklista och enkelt tidsdiagram, helt utan externa paket."""
        try:
            host = urlsplit(normalize_url(self.selected_site["url"] if self.selected_site else "")).hostname
        except ValueError as exc:
            messagebox.showerror("Felaktig adress", str(exc))
            return
        records = history_for(host)
        if not records:
            messagebox.showinfo("Historik", "Ingen sparad historik för denna domän ännu.")
            return

        win = tk.Toplevel(
            self.root,
            class_="RWB-CyberGuard-Alpha6"
        )
        win.title(f"CyberGuard – Historik för {host}")
        win.geometry("1040x790")
        win.minsize(780, 620)
        win.transient(self.root)
        wrapper = ttk.Frame(win, padding=14)
        wrapper.pack(fill="both", expand=True)
        ttk.Label(wrapper, text=f"Säkerhetshistorik: {host}",
                  font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 6))
        ttk.Label(wrapper, text="Antal identifierade headers och förbättringar per kontroll – inte en riskpoäng.").pack(anchor="w")
        treeframe = ttk.Frame(wrapper)
        treeframe.pack(fill="both", expand=False, pady=(10, 8))
        cols = ("time", "pages", "passed", "missing", "cert")
        tree = ttk.Treeview(treeframe, columns=cols, show="headings", height=9)
        for key, title, width in [
            ("time", "Tidpunkt (UTC)", 220), ("pages", "Sidor", 70),
            ("passed", "Skydd", 85), ("missing", "Att granska", 105),
            ("cert", "Certifikat t.o.m.", 155)]:
            tree.heading(key, text=title)
            tree.column(key, width=width, anchor="center" if key != "time" else "w")
        scrollbar = ttk.Scrollbar(treeframe, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for i, r in enumerate(records):
            pages, passed, missing = history_summary(r)
            tree.insert("", "end", iid=str(i), values=(r.get("time", "")[:19], pages,
                                                       passed, missing, r.get("tls_expiry", "–")))
        canvas = tk.Canvas(wrapper, height=215, bg="white", highlightthickness=1,
                           highlightbackground="#c5c5c5")
        canvas.pack(fill="x", pady=(0, 8))
        def redraw(_event=None):
            canvas.delete("all")
            width = max(canvas.winfo_width(), 320)
            height = max(canvas.winfo_height(), 180)
            left, right, top, bottom = 55, width - 20, 20, height - 35
            canvas.create_line(left, top, left, bottom, fill="#555")
            canvas.create_line(left, bottom, right, bottom, fill="#555")
            samples = [history_summary(r) for r in records]
            maximum = max(1, *(p + m for _, p, m in samples))
            for tick in range(5):
                y = bottom - (bottom-top) * tick / 4
                canvas.create_text(left-9, y, text=str(round(maximum*tick/4)), anchor="e", fill="#555")
                canvas.create_line(left, y, right, y, fill="#eee")
            n = len(samples)
            slot = (right-left) / max(n, 1)
            bw = min(17, slot*0.3)
            for i, (_, passed, missing) in enumerate(samples):
                cx = left + slot*(i+0.5)
                for x1, value, color in [(cx-bw-2, passed, "#27834b"),
                                         (cx+2, missing, "#bc8330")]:
                    y = bottom - (bottom-top)*value/maximum
                    canvas.create_rectangle(x1, y, x1+bw, bottom, fill=color, outline="")
                if n <= 15 or i % max(1, n//12) == 0:
                    canvas.create_text(cx, bottom+12, text=str(i+1), fill="#444", font=("Arial", 8))
            canvas.create_text(left+6, 9, text="Grönt = identifierade skydd   Orange = att granska",
                               anchor="w", fill="#333", font=("Arial", 9))
        canvas.bind("<Configure>", redraw)
        def details(_event=None):
            selection = tree.selection()
            if not selection:
                return
            i = int(selection[0])
            record = records[i]
            previous = records[i-1] if i else None
            lines = [f"Kontroll: {record.get('time', '')}", "",
                     "FÖRÄNDRINGAR JÄMFÖRT MED FÖREGÅENDE SPARADE KONTROLL"]
            lines.extend(compare_results(previous, record))
            lines.extend(compare_certificates(previous, record))
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            detail.insert("end", "\n".join(lines))
            detail.configure(state="disabled")
        tree.bind("<<TreeviewSelect>>", details)
        ttk.Label(wrapper, text="Markerad kontroll – jämförelse", font=("Arial", 11, "bold")).pack(anchor="w")
        detail = scrolledtext.ScrolledText(wrapper, height=14, wrap="word", font=("DejaVu Sans Mono", 10))
        detail.pack(fill="both", expand=True)
        detail.configure(state="disabled")
        tree.selection_set(str(len(records)-1))
        details()

    def save(self):
        if not self.current_report:
            return
        create_export_dirs()
        filename = filedialog.asksaveasfilename(
            title="Spara säkerhetsrapport", defaultextension=".txt",
            filetypes=[("Textfiler", "*.txt")],
            initialfile=dated_name("CyberGuard_Rapport", "txt").name, initialdir=str(REPORT_DIR))
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(self.current_report + "\n")
            messagebox.showinfo("Rapport sparad", "Rapporten har sparats.")
        except OSError as exc:
            messagebox.showerror("Kunde inte spara", str(exc))


if __name__ == "__main__":
    try:
        create_export_dirs()
    except OSError as exc:
        raise SystemExit(f"Kunde inte skapa programmets datamappar: {exc}")
    root = tk.Tk(className="RWB-CyberGuard-Alpha6")
    root.tk.call("tk", "appname", "RWB-CyberGuard-Alpha6")
    CyberGuardApp(root)
    def focus_window():
        try:
            root.lift()
            root.attributes("-topmost", True)
            root.focus_force()
            root.after(800, lambda: root.attributes("-topmost", False))
        except tk.TclError:
            pass
    root.after(300, focus_window)
    root.mainloop()
