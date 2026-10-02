"""Build CRAFT's editable vector diagrams and matching landscape PDF."""

from __future__ import annotations

import math
import os
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parent
SVG_DIR = ROOT / "svg"
WIDTH, HEIGHT = 1600, 1000
SCALE = 0.72
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)

INK = "#18334A"
MUTED = "#586F7F"
PAPER = "#F6F9FB"
WHITE = "#FFFFFF"
LINE = "#D5E0E7"
HEADER = "#112D43"
HEADER_MUTED = "#C2D7E4"
TEAL = "#007F7C"
TEAL_LIGHT = "#E2F2EF"
BLUE = "#315DC0"
BLUE_LIGHT = "#E3EBFA"
PURPLE = "#7752A3"


def fonts():
    fonts_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    candidates = {
        "regular": ("segoeui.ttf", "DejaVuSans.ttf"),
        "semibold": ("seguisb.ttf", "DejaVuSans-Bold.ttf"),
        "mono": ("consola.ttf", "DejaVuSansMono.ttf"),
    }
    roots = [fonts_dir, Path("/usr/share/fonts/truetype/dejavu")]
    for name, files in candidates.items():
        font = next((base / file for base in roots for file in files if (base / file).is_file()), None)
        if font is None:
            raise RuntimeError(f"A font for {name} is required")
        pdfmetrics.registerFont(TTFont(name, str(font)))


class Page:
    def __init__(self, pdf, slug, number, title, subtitle, description):
        self.pdf = pdf
        self.slug = slug
        self.number = number
        self.text_boxes = []
        self.svg = ET.Element(f"{{{NS}}}svg", {
            "width": str(WIDTH), "height": str(HEIGHT), "viewBox": f"0 0 {WIDTH} {HEIGHT}",
            "role": "img", "aria-labelledby": f"{slug}-title {slug}-desc",
        })
        ET.SubElement(self.svg, f"{{{NS}}}title", {"id": f"{slug}-title"}).text = title
        ET.SubElement(self.svg, f"{{{NS}}}desc", {"id": f"{slug}-desc"}).text = description
        self.pdf.saveState()
        self.pdf.scale(SCALE, SCALE)
        self.pdf.bookmarkPage(slug)
        self.pdf.addOutlineEntry(title, slug)
        self.rect(0, 0, WIDTH, HEIGHT, PAPER)
        self.rect(0, 0, WIDTH, 181, HEADER)
        self.rect(64, 40, 5, 26, TEAL)
        self.text(84, 38, "CRAFT", 22, WHITE, "semibold")
        self.text(193, 45, "CERTIFICATE REQUEST AGENT FOR TICKETS", 13, HEADER_MUTED)
        self.text(1536, 42, f"{number:02d} / 04", 17, HEADER_MUTED, align="right")
        self.text(64, 84, title, 38, WHITE, "semibold", max_width=1472)
        self.text(64, 139, subtitle, 18, HEADER_MUTED, max_width=1472)

    def element(self, tag, attributes):
        return ET.SubElement(self.svg, f"{{{NS}}}{tag}", {k: str(v) for k, v in attributes.items()})

    def rect(self, x, y, w, h, fill=WHITE, stroke=None, radius=0, width=1):
        self.pdf.setFillColor(HexColor(fill or WHITE))
        if stroke:
            self.pdf.setStrokeColor(HexColor(stroke))
        self.pdf.setLineWidth(width)
        if radius:
            self.pdf.roundRect(x, HEIGHT - y - h, w, h, radius, fill=int(bool(fill)), stroke=int(bool(stroke)))
        else:
            self.pdf.rect(x, HEIGHT - y - h, w, h, fill=int(bool(fill)), stroke=int(bool(stroke)))
        self.element("rect", {
            "x": x, "y": y, "width": w, "height": h, "rx": radius,
            "fill": fill or "none", "stroke": stroke or "none", "stroke-width": width,
        })

    def circle(self, x, y, radius, fill, stroke=None, width=1):
        self.pdf.setFillColor(HexColor(fill))
        if stroke:
            self.pdf.setStrokeColor(HexColor(stroke))
        self.pdf.setLineWidth(width)
        self.pdf.circle(x, HEIGHT - y, radius, fill=1, stroke=int(bool(stroke)))
        self.element("circle", {
            "cx": x, "cy": y, "r": radius, "fill": fill,
            "stroke": stroke or "none", "stroke-width": width,
        })

    def text(self, x, y, value, size=18, color=INK, font="regular", align="left", max_width=None):
        extent = pdfmetrics.stringWidth(value, font, size)
        if max_width is not None and extent > max_width + 0.1:
            raise ValueError(f"{self.slug}: text exceeds {max_width}: {value} ({extent:.1f})")
        left = x if align == "left" else x - extent if align == "right" else x - extent / 2
        if left < 0 or left + extent > WIDTH + 0.1 or y < 0 or y + size > HEIGHT:
            raise ValueError(f"{self.slug}: text outside page: {value}")
        baseline = y + size * 0.81
        self.pdf.setFillColor(HexColor(color))
        self.pdf.setFont(font, size)
        self.pdf.drawString(left, HEIGHT - baseline, value)
        family = "Consolas, 'DejaVu Sans Mono', monospace" if font == "mono" else "'Segoe UI', Arial, sans-serif"
        attributes = {
            "x": x, "y": baseline, "font-size": size, "font-family": family, "fill": color,
            "font-weight": "600" if font == "semibold" else "400",
            "text-anchor": {"left": "start", "center": "middle", "right": "end"}[align],
        }
        self.element("text", attributes).text = value
        self.text_boxes.append((left, y, extent, size, value))

    def lines(self, x, y, values, size=18, color=INK, leading=None, font="regular", max_width=None):
        for index, value in enumerate(values):
            self.text(x, y + index * (leading or size * 1.4), value, size, color, font, max_width=max_width)

    def line(self, points, color=LINE, width=1.5, dashed=False):
        self.pdf.setStrokeColor(HexColor(color))
        self.pdf.setLineWidth(width)
        self.pdf.setLineCap(1)
        self.pdf.setLineJoin(1)
        self.pdf.setDash([5, 6] if dashed else [])
        path = self.pdf.beginPath()
        path.moveTo(points[0][0], HEIGHT - points[0][1])
        for x, y in points[1:]:
            path.lineTo(x, HEIGHT - y)
        self.pdf.drawPath(path)
        self.pdf.setDash([])
        attributes = {
            "points": " ".join(f"{x},{y}" for x, y in points), "fill": "none", "stroke": color,
            "stroke-width": width, "stroke-linecap": "round", "stroke-linejoin": "round",
        }
        if dashed:
            attributes["stroke-dasharray"] = "5 6"
        self.element("polyline", attributes)

    def polygon(self, points, fill):
        self.pdf.setFillColor(HexColor(fill))
        path = self.pdf.beginPath()
        path.moveTo(points[0][0], HEIGHT - points[0][1])
        for x, y in points[1:]:
            path.lineTo(x, HEIGHT - y)
        path.close()
        self.pdf.drawPath(path, fill=1, stroke=0)
        self.element("polygon", {"points": " ".join(f"{x},{y}" for x, y in points), "fill": fill})

    def arrow(self, points, color=INK, width=2, dashed=False, both=False, head=8):
        self.line(points, color, width, dashed)
        ends = [(points[-2], points[-1])]
        if both:
            ends.append((points[1], points[0]))
        for previous, end in ends:
            angle = math.atan2(end[1] - previous[1], end[0] - previous[0])
            self.polygon([
                end,
                (end[0] - head * math.cos(angle) + head * 0.55 * math.sin(angle),
                 end[1] - head * math.sin(angle) - head * 0.55 * math.cos(angle)),
                (end[0] - head * math.cos(angle) - head * 0.55 * math.sin(angle),
                 end[1] - head * math.sin(angle) + head * 0.55 * math.cos(angle)),
            ], color)

    def node(self, x, y, w, h, title, body, color=INK, fill=WHITE, dark=False, title_size=23):
        self.rect(x, y, w, h, fill, LINE if not dark else None, radius=12)
        self.rect(x + 20, y + 21, 4, 23, color)
        self.text(x + 36, y + 20, title, title_size, WHITE if dark else INK, "semibold", max_width=w - 55)
        self.lines(x + 22, y + 58, body, 17, HEADER_MUTED if dark else MUTED, leading=25, max_width=w - 44)

    def number_badge(self, x, y, value, color=INK):
        self.circle(x, y, 15, color)
        self.text(x, y - 10, str(value), 19, WHITE, "semibold", align="center")

    def message(self, x1, x2, y, label, color=INK, dashed=False, label_x=None, size=17):
        self.arrow([(x1, y), (x2, y)], color, 1.8, dashed)
        left = min(x1, x2) + 16 if label_x is None else label_x
        extent = pdfmetrics.stringWidth(label, "regular", size)
        self.rect(left - 5, y - 26, extent + 10, size + 4, PAPER)
        self.text(left, y - 24, label, size, INK)

    def footer(self, source):
        self.line([(64, 956), (1536, 956)], LINE, 1)
        self.text(64, 971, "SOURCE  " + source, 13, MUTED, max_width=1310)
        self.text(1536, 969, f"CRAFT  /  {self.number:02d}", 14, MUTED, "semibold", align="right")
        self.pdf.restoreState()
        self.pdf.showPage()
        ET.indent(self.svg, space="  ")
        ET.ElementTree(self.svg).write(SVG_DIR / f"{self.slug}.svg", encoding="utf-8", xml_declaration=True)


def overview(pdf):
    p = Page(pdf, "01-system-overview", 1, "A temporary certificate. A reusable ticket workflow.",
             "A ticket-granting ticket (TGT) lets approved Linux users request service tickets "
             "without storing AD passwords.",
             "CRAFT separates the Linux caller, its dedicated enrollment worker, and the user ticket cache. "
             "The worker resolves the user in Active Directory, enrolls through CES and the CA, authenticates "
             "with PKINIT at the KDC, and publishes a caller-owned cache. Applications use that TGT to request "
             "service tickets and authenticate to services under the user's existing permissions.")
    p.text(94, 221, "TRUSTED LINUX HOST", 15, MUTED, "semibold")
    p.text(1126, 221, "ACTIVE DIRECTORY + PKI", 15, MUTED, "semibold")
    p.line([(94, 255), (790, 255)])
    p.line([(1126, 255), (1506, 255)])

    p.node(94, 298, 300, 124, "Approved Linux user",
           ["craft: real UID / NSS checks", "Parent drops to caller"], title_size=21)
    p.rect(470, 298, 320, 278, HEADER, radius=12)
    p.text(494, 322, "craft-worker", 27, WHITE, "semibold")
    p.text(494, 361, "Dedicated craft Unix account", 17, HEADER_MUTED)
    p.line([(494, 393), (766, 393)], "#406074", 1)
    p.lines(494, 412, ["Fresh RSA-3072 key + CSR", "Enrollment-agent signature", "Issued certificate checks",
                       "PKINIT + returned TGT checks"], 17, WHITE, leading=28, max_width=272)
    p.text(494, 546, "Temporary user certificate / key", 15, HEADER_MUTED, max_width=272)
    p.node(94, 632, 300, 136, "User credential cache",
           [".krb5cc_craft", "TGT + session key", "Caller-owned / mode 0600"], color=BLUE, title_size=21)
    p.node(470, 804, 320, 100, "Kerberos-aware app", ["Loads cache via KRB5CCNAME"],
           color=BLUE, title_size=23)

    p.node(1126, 298, 380, 96, "Active Directory", ["Global Catalog: UPN + SID"], color=TEAL)
    p.node(1126, 442, 380, 110, "AD CS / CES + CA",
           ["Restricted template + recipients", "Issues short-lived user certificate"], color=TEAL)
    p.node(1126, 610, 380, 110, "Domain controller / KDC",
           ["Issues the user's TGT", "Issues / renews tickets by policy"], color=BLUE, title_size=22)
    p.node(1126, 804, 380, 100, "Kerberos-enabled services",
           ["SMB / LDAP / HTTP; existing user rights"], color=BLUE, title_size=21)

    p.arrow([(394, 354), (470, 354)], INK)
    p.number_badge(432, 326, 1)
    p.arrow([(790, 347), (1126, 347)], TEAL, both=True)
    p.text(825, 316, "2  Resolve caller identity", 18, max_width=295)
    p.arrow([(790, 500), (1126, 500)], TEAL, both=True)
    p.text(825, 468, "3  HTTPS / MS-WSTEP", 18, max_width=295)
    p.arrow([(790, 550), (910, 550), (910, 667), (1126, 667)], TEAL, both=True)
    p.text(933, 617, "4  PKINIT", 18)
    p.text(933, 643, "User certificate", 16, MUTED)
    p.arrow([(630, 576), (630, 690), (394, 690)], BLUE)
    p.text(430, 710, "5  Publish via caller", 18)
    p.arrow([(244, 768), (244, 854), (470, 854)], BLUE)
    p.text(267, 821, "6  Select cache", 18)
    p.arrow([(790, 826), (1028, 826), (1028, 697), (1126, 697)], BLUE, both=True)
    p.lines(819, 756, ["7  Request / receive", "a service ticket"], 18, leading=26, max_width=195)
    p.arrow([(790, 882), (1126, 882)], BLUE)
    p.text(823, 849, "8  Present service ticket", 18, max_width=290)
    p.text(94, 926, "Trust comes from the managed host, enrollment credentials and CA restrictions. "
           "CRAFT performs no MFA challenge.",
           16, MUTED, max_width=1412)
    p.footer("launcher.cpp: main; worker.cpp: main, lookup_ad_user, get_tgt; "
             "source/README.md: Access Active Directory Resources")


def acquisition(pdf):
    p = Page(pdf, "02-enrollment-sequence", 2, "From a Linux account to a validated user TGT.",
             "Successful exchange. Time flows downward; spacing represents order, not network latency.",
             "Sequence: validate the real caller and drop privileges; obtain a separate short-lived transport "
             "TGT using the submission keytab; resolve UPN and SID in the Global Catalog; generate and sign an "
             "EOBO request; enroll through CES; validate the certificate; perform user PKINIT; validate the TGT; "
             "return cache bytes to the unprivileged caller and publish atomically. Solid arrows are requests; "
             "dashed arrows are responses. CES transport uses Negotiate or a separate TLS client identity.")
    lanes = [
        (240, 270, "craft / caller", "launch + cache writer", INK),
        (570, 250, "craft-worker", "craft service account", TEAL),
        (865, 190, "Global Catalog", "AD identity", TEAL),
        (1120, 240, "CES + CA", "certificate issuance", TEAL),
        (1430, 190, "KDC", "Kerberos authority", BLUE),
    ]
    for x, width, title, detail, color in lanes:
        p.rect(x - width / 2, 213, width, 64, WHITE, LINE, radius=9)
        p.text(x, 226, title, 21, color, "semibold", align="center")
        p.text(x, 254, detail, 15, MUTED, align="center")
        p.line([(x, 284), (x, 833)], LINE, 1.1, dashed=True)
    p.rect(565, 319, 10, 499, TEAL_LIGHT)
    p.rect(235, 309, 10, 516, BLUE_LIGHT)

    p.number_badge(70, 319, 1)
    p.message(245, 565, 319, "UID / NSS; drop privileges", label_x=257, size=17)

    p.number_badge(70, 385, 2)
    p.message(575, 1430, 369, "Authenticate directory/CES account with submitter.keytab", color=INK)
    p.message(1430, 575, 401, "Transport TGT: 5 min requested; held only in worker memory", color=INK,
              dashed=True, label_x=872, size=16)

    p.number_badge(70, 453, 3)
    p.message(575, 865, 437, "LDAP / GSSAPI: query caller", color=TEAL, size=17)
    p.message(865, 575, 469, "Unique AD UPN + SID", color=TEAL, dashed=True, size=17)

    p.number_badge(70, 528, 4)
    p.rect(495, 497, 712, 62, TEAL_LIGHT, radius=9)
    p.lines(518, 506, ["Generate a fresh RSA-3072 key and CSR.",
                       "Enrollment-agent CMS signature binds DOMAIN\\user."], 18, leading=25, max_width=665)

    p.number_badge(70, 605, 5)
    p.message(575, 1120, 590, "HTTPS / MS-WSTEP: signed enrollment request", color=TEAL, size=17)
    p.message(1120, 575, 622, "User certificate: CA supplies SID + template", color=TEAL, dashed=True, size=17)
    p.text(1246, 569, "CES transport:", 15, MUTED)
    p.lines(1246, 591, ["Negotiate or", "separate mTLS identity"], 15, MUTED, leading=22, max_width=282)

    p.number_badge(70, 678, 6)
    p.rect(495, 647, 712, 62, TEAL_LIGHT, radius=9)
    p.lines(518, 656, ["Validate key, UPN, SID, template, EKUs and lifetime.",
                       "Verify certificate chain and configured CRLs."], 18, leading=25, max_width=665)

    p.number_badge(70, 753, 7)
    p.message(575, 1430, 738, "PKINIT using sealed in-memory certificate + key", color=BLUE, size=17)
    p.message(1430, 575, 770, "User TGT + session key; KDC sets actual ticket times", color=BLUE,
              dashed=True, label_x=909, size=17)

    p.number_badge(70, 818, 8)
    p.message(565, 245, 818, "Validate TGT; return cache bytes", color=BLUE, dashed=True, label_x=258, size=17)
    p.text(621, 799, "Principal / flags / AES / lifetime", 17, MUTED)
    p.text(1100, 799, "Strict default rejects shorter grants", 17, MUTED)

    p.rect(105, 853, 1420, 74, BLUE_LIGHT, radius=10)
    p.text(128, 866, "Publish only after successful validation", 23, INK, "semibold")
    p.text(128, 898, "Caller writes a mode-0600 staging file, then atomically replaces .krb5cc_craft. "
           "Output is the FILE: cache name.",
           18, INK, max_width=1374)
    p.footer("launcher.cpp: main; worker.cpp: acquire_transport, main, validate_leaf, validate_tgt; "
             "common.hpp: publish_cache")


def timing(pdf):
    p = Page(pdf, "03-credential-timing", 3, "One acquisition, several independent clocks.",
             "Default profile: request 10 h / 7 d. Certificate validity and KDC policy constrain the initial grant.",
             "The certificate and private key remain on the client only for enrollment and PKINIT. Certificate "
             "validity is capped at ten hours total, including backdating. In a full-grant example, initial TGT "
             "validity spans hours zero to ten; renewal around hour eight grants a TGT ending around hour eighteen; "
             "renewal around hour sixteen grants one ending around hour twenty-six. The original absolute "
             "renewal deadline remains day seven. Fresh enrollment around day six begins a new renewal window "
             "that can extend to day thirteen. These are idealized schedule illustrations, not measurements.")
    p.rect(64, 208, 1472, 78, TEAL_LIGHT, radius=10)
    p.text(84, 222, "USER CERTIFICATE + PRIVATE KEY", 14, TEAL, "semibold")
    p.text(84, 246, "Client residency lasts only for enrollment and PKINIT.", 23, INK, "semibold")
    p.text(1050, 223, "Certificate validity: <= 10 h total", 18, INK)
    p.text(1050, 252, "CA backdating consumes this allowance.", 16, MUTED)

    p.text(64, 311, "01 / HOURS", 14, BLUE, "semibold")
    p.text(284, 306, "Renew before expiry", 24, INK, "semibold")
    p.text(1536, 311, "Illustrative full 10 h grants", 17, MUTED, align="right")
    start, end = 284, 1536
    hour = lambda value: start + (end - start) * value / 28
    for value in range(0, 29, 4):
        x = hour(value)
        p.line([(x, 373), (x, 620)], LINE, 1)
        p.text(x, 345, f"{value} h", 16, MUTED,
               align="left" if value == 0 else "right" if value == 28 else "center")
    p.line([(start, 372), (end, 372)], LINE, 1)
    for index, (begin, y, title, expiry) in enumerate([
        (0, 390, "Initial TGT", 10), (8, 475, "Renewal 1", 18), (16, 560, "Renewal 2", 26),
    ]):
        p.text(64, y + 9, title, 22, INK, "semibold")
        p.text(64, y + 38, "Selected until refresh", 15, MUTED)
        p.rect(hour(begin), y, hour(expiry) - hour(begin), 48, BLUE_LIGHT, radius=7)
        p.rect(hour(begin), y, hour(begin + 8) - hour(begin), 48, BLUE, radius=7)
        p.text(hour(begin) + 19, y + 15, f"TGT valid until hour {expiry}", 18, WHITE, "semibold")
        if index < 2:
            trigger = begin + 8
            p.arrow([(hour(trigger), y + 49), (hour(trigger), y + 83)], PURPLE, 2, head=7)
            p.text(hour(trigger) + 12, y + 56, f"~{trigger} h: renew", 16, PURPLE)
        else:
            p.text(hour(24) + 8, y + 54, "Next renewal ~24 h", 15, PURPLE)
    p.rect(64, 639, 20, 12, BLUE)
    p.text(94, 634, "Selected credential", 16, MUTED)
    p.rect(287, 639, 20, 12, BLUE_LIGHT)
    p.text(317, 634, "Superseded validity", 16, MUTED)
    p.text(1536, 633, "Renewal advances expiry; renew-till stays fixed.", 18, INK, "semibold", align="right")

    p.text(64, 691, "02 / DAYS", 14, TEAL, "semibold")
    p.text(284, 684, "Start a fresh cycle near the renewal deadline", 24, INK, "semibold")
    day = lambda value: start + (end - start) * value / 8
    for value in range(9):
        x = day(value)
        p.line([(x, 750), (x, 892)], LINE, 1)
        p.text(x, 725, f"Day {value}", 16, MUTED,
               align="left" if value == 0 else "right" if value == 8 else "center")
    p.line([(start, 749), (end, 749)], LINE, 1)
    p.text(64, 776, "Enrollment 1", 22, INK, "semibold")
    p.text(64, 805, "Renewal window", 15, MUTED)
    p.rect(day(0), 773, day(7) - day(0), 42, BLUE_LIGHT, radius=6)
    p.rect(day(0), 773, day(6) - day(0), 42, BLUE, radius=6)
    p.text(day(0) + 18, 785, "Original renewal window", 18, WHITE, "semibold")
    p.text(day(7) - 10, 785, "Deadline", 17, BLUE, align="right")
    p.arrow([(day(6), 816), (day(6), 847)], TEAL, 2, head=7)
    p.text(day(6) + 13, 820, "Enroll ~day 6", 17, TEAL, "semibold")
    p.text(64, 852, "Enrollment 2", 22, INK, "semibold")
    p.text(64, 881, "Fresh certificate + TGT", 15, MUTED)
    p.polygon([(day(6), 849), (end - 15, 849), (end, 870), (end - 15, 891), (day(6), 891)], TEAL)
    p.text(day(6) + 18, 861, "New 7-day window", 18, WHITE, "semibold")
    p.text(1536, 902, "Continues to ~day 13", 15, MUTED, align="right")
    p.text(64, 929, "Renewal uses the cached ticket and session key. "
           "Certificate expiry or cleanup does not revoke an issued ticket.",
           17, INK, max_width=1472)
    p.footer("maintain.cpp: schedule, validate_renewed_tgt; worker.cpp: get_tgt; config.example: lifetime defaults")


def maintenance(pdf):
    p = Page(pdf, "04-job-maintenance", 4, "Keep a job authenticated, then stop with it.",
             "craft-maintain runs as the caller, coordinates one shared cache per UID, and watches a live process.",
             "The maintainer starts once for a watched job PID. A usable cache and detached loop are required "
             "before startup returns successfully. Due renewable TGTs renew at the KDC using the cached ticket "
             "and session key. Missing or expired TGTs, the rollover window, or nonextendible tickets near expiry "
             "trigger fresh enrollment through craft. Due renewal takes priority over rollover. Successful "
             "updates atomically replace the cache. Renewal retains usable service tickets; fresh enrollment "
             "replaces the cache. Failure keeps existing credentials and schedules retries. Job exit stops "
             "maintenance but leaves the cache. Applications need to reload refreshed credentials.")
    p.rect(64, 210, 1472, 104, HEADER, radius=11)
    p.text(88, 220, "START ONCE / WATCH A SHELL THAT STAYS ALIVE FOR THE JOB", 13, HEADER_MUTED, "semibold")
    p.text(88, 244, "job_pid=$$", 18, WHITE, "mono")
    p.text(88, 265, 'cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"', 18, WHITE, "mono")
    p.text(88, 287, 'export KRB5CCNAME="$cache"', 18, WHITE, "mono")
    p.lines(1120, 244, ["Returns when usable credentials", "and background maintenance", "are ready."],
            17, HEADER_MUTED, leading=23, max_width=390)

    p.text(64, 349, "01 / RENEW", 15, BLUE, "semibold")
    p.text(64, 379, "Use the current ticket", 28, INK, "semibold")
    p.lines(64, 425, ["When a renewable TGT has <=20% of its lifetime left",
                     "(capped at 2 h), and its expiry can extend."],
            19, INK, leading=27, max_width=704)
    p.text(64, 482, "A renewal error retries here; no immediate enrollment.", 16, MUTED, max_width=704)
    p.line([(790, 347), (790, 642)], LINE, 1)
    p.text(824, 349, "02 / FRESH ENROLLMENT", 15, TEAL, "semibold")
    p.text(824, 379, "Obtain fresh credentials", 28, INK, "semibold")
    p.lines(824, 425, ["Missing or expired TGT; renewal deadline is near;",
                      "or a ticket that cannot extend is nearing expiry."],
            19, INK, leading=27, max_width=710)
    p.text(824, 482, "Rollover margin: 1/7 of the renewal window, capped at 1 day.", 16, MUTED, max_width=710)

    for x, w, title, detail in [(64, 191, "Cached TGT", "+ session key"),
                               (315, 178, "KDC", "renew request"),
                               (553, 215, "Validated TGT", "new expiry")]:
        p.rect(x, 522, w, 79, BLUE_LIGHT, radius=9)
        p.text(x + w / 2, 536, title, 21, INK, "semibold", align="center")
        p.text(x + w / 2, 569, detail, 17, MUTED, align="center")
    p.arrow([(255, 561), (315, 561)], BLUE)
    p.arrow([(493, 561), (553, 561)], BLUE)
    p.lines(64, 615, ["Renew-till never moves later.", "Retain usable service tickets."],
            18, BLUE, leading=24, max_width=704)

    for x, w, title, detail in [(824, 178, "Run craft", "fresh key + CSR"),
                               (1062, 218, "GC + CES / CA", "enroll certificate"),
                               (1340, 196, "KDC / PKINIT", "new user TGT")]:
        p.rect(x, 522, w, 79, TEAL_LIGHT, radius=9)
        p.text(x + w / 2, 536, title, 21, INK, "semibold", align="center")
        p.text(x + w / 2, 569, detail, 17, MUTED, align="center")
    p.arrow([(1002, 561), (1062, 561)], TEAL)
    p.arrow([(1280, 561), (1340, 561)], TEAL)
    p.lines(824, 615, ["New renewal window.", "Replace the shared cache."],
            18, TEAL, leading=24, max_width=710)
    p.text(64, 665, "A due renewal takes priority during rollover, "
           "keeping usable credentials alive while enrollment is delayed.",
           18, MUTED, max_width=1472)

    p.rect(64, 708, 1472, 92, WHITE, LINE, radius=11)
    p.text(84, 724, "Successful refresh", 22, INK, "semibold")
    p.text(84, 759, "Publish atomically to .krb5cc_craft (caller-owned, mode 0600).", 18, INK, max_width=684)
    p.line([(790, 725), (790, 782)], LINE, 1)
    p.text(824, 724, "Refresh failure", 22, INK, "semibold")
    p.text(824, 759, "Keep the existing cache and retry; the job continues.", 18, INK, max_width=692)

    notes = [
        (64, 460, "RETRY", ["Renewal: ~30 s to 5 min + jitter.", "Enrollment cooldown: 1 min to 1 h."]),
        (552, 484, "STOP", ["Watched PID exits, duration ends or signal.",
                            "Maintainer stops; the shared cache remains."]),
        (1064, 472, "APPLICATION", ["Reload credentials when authenticating again.",
                                   "Access follows the user's service permissions."]),
    ]
    for x, width, label, lines in notes:
        p.line([(x, 830), (x + width, 830)], LINE, 1.3)
        p.text(x, 845, label, 14, MUTED, "semibold")
        p.lines(x, 873, lines, 17, INK, leading=27, max_width=width)
    p.footer("maintain.cpp: schedule, update, renewed_cache, detached loop; "
             "common.hpp: publish_cache; source/README.md: Long-running jobs")


def main():
    fonts()
    SVG_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = ROOT / "CRAFT-Timing-and-Architecture.pdf"
    pdf = canvas.Canvas(str(pdf_path), pagesize=(WIDTH * SCALE, HEIGHT * SCALE), pageCompression=1)
    pdf.setTitle("CRAFT | Timing and Architecture")
    pdf.setAuthor("CRAFT")
    pdf.setSubject("Source-grounded architecture, enrollment, credential timing and job maintenance diagrams")
    pdf.setCreator("CRAFT vector diagram builder")
    for page in (overview, acquisition, timing, maintenance):
        page(pdf)
    pdf.save()
    with ZipFile(ROOT / "CRAFT-Editable-Diagrams.zip", "w", ZIP_DEFLATED) as archive:
        for svg in sorted(SVG_DIR.glob("*.svg")):
            archive.write(svg, "svg/" + svg.name)
        archive.write(Path(__file__), "build_craft_diagrams.py")
    print(f"Created {pdf_path}")
    print(f"Created {len(list(SVG_DIR.glob('*.svg')))} SVG diagrams and editable source bundle")


if __name__ == "__main__":
    main()
