"""Build CRAFT's editable vector diagrams and matching landscape PDF."""

from __future__ import annotations

import math
import os
from pathlib import Path
from xml.etree import ElementTree as ET

from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parent
SVG_DIR = ROOT / "diagrams"
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
        self.text(1536, 42, f"{number:02d} / 06", 17, HEADER_MUTED, align="right")
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
    p = Page(pdf, "01-system-overview", 1, "Three Linux operating modes",
             "A supplied PEM pair takes priority. Only an absent pair selects the configured privileged mechanism.",
             "CRAFT checks the actual Linux caller's NSS home for user.pem and user.key. A complete pair "
             "uses mode 3's unprivileged acquisition path, including on privileged installations. Partial, "
             "unsafe or invalid inputs fail and retain the cache. If both files are absent, a setuid installation "
             "selects mode 1 enrollment or mode 2 credential linking from mechanism. All modes use PKINIT for "
             "the fixed caller principal, validate the KDC and returned TGT, then publish as the caller.")
    p.node(64, 220, 350, 125, "Invoke craft as the user",
           ["Real UID, NSS name and home", "No arguments; no sudo"], title_size=23)
    p.node(480, 220, 736, 125, "Check user.pem and user.key in the NSS home",
           ["~/.config/craft/user.pem + user.key",
               "Complete pair takes priority on every installation"],
               color=BLUE,
               title_size=26)
    p.arrow([(414, 282), (480, 282)])
    p.arrow([(670, 345), (670, 428)], TEAL)
    p.text(695, 375, "BOTH FILES ABSENT", 19, TEAL, "semibold")
    p.node(190, 428, 736, 87, "Select the configured privileged mechanism",
           ["Requires setuid launcher, craft service account and /run/craft"], color=TEAL, title_size=25)
    p.arrow([(1080, 345), (1080, 392), (1308, 392), (1308, 560)], BLUE)
    p.text(1102, 418, "COMPLETE PAIR", 19, BLUE, "semibold")
    p.lines(64, 370, ["Partial, unsafe or invalid:", "fail and retain cache."], 21, MUTED, leading=30)
    p.arrow([(370, 515), (370, 537), (291, 537), (291, 560)], TEAL)
    p.arrow([(765, 515), (765, 537), (799, 537), (799, 560)], PURPLE)
    p.node(64, 560, 455, 233, "1  Privileged enrollment",
           ["mechanism=enrollment", "Service account: GC + agent + CES", "CA issues temporary user certificate",
            "PKINIT authenticates that certificate",
                "CA enforces recipient restrictions"],
                color=TEAL,
                fill=TEAL_LIGHT,
                title_size=26)
    p.node(572, 560, 455, 233, "2  Privileged credential linking",
           ["mechanism=key_trust", "Service account: writable DC + keytab", "Add temporary msDS-KeyCredentialLink",
            "Key Trust PKINIT; remove the entry", "AD enforces attribute-write scope"], color=PURPLE, title_size=23)
    p.node(1080, 560, 455, 233, "3  Unprivileged Windows PEM",
           ["Windows: user enrollment + export",
               "Securely transfer certificate and key",
               "Linux: caller validates and uses pair",
            "PKINIT uses KDC account mapping",
                "Supplied PEM files remain in place"],
                color=BLUE,
                fill=BLUE_LIGHT,
                title_size=24)
    for x in (291, 799, 1308):
        p.arrow([(x, 793), (x, 816), (799, 816), (799, 843)], BLUE)
    p.node(330, 843, 940, 95, "Validate the user TGT and publish the cache as the caller",
           [(
               'Fixed principal: Linux username @ realm; .krb5cc_craft mode 0600; select'
               ' with KRB5CCNAME'
           )], color=BLUE, title_size=27)
    p.footer("source/README.md: Mode selection and process boundaries; mode-specific setup recipes")


def acquisition(pdf):
    p = Page(pdf, "02-enrollment-sequence", 2, "Mode 1  Privileged certificate enrollment",
             (
                 'Linux orchestrates CA enrollment first, then PKINIT. Select '
                 'mechanism=enrollment with both home PEM files absent.'
             ),
             "The setuid launcher starts the worker as the dedicated service account. A directory keytab "
             "authenticates the UPN lookup and CES Negotiate; separate mTLS may authenticate CES instead. "
             "CRAFT generates a fresh RSA-3072 key, signs an EOBO request with the enrollment-agent key, "
             "and obtains the restricted user certificate through CES and AD CS. It validates the certificate "
             "and performs PKINIT for the caller. Only validated TGT bytes return to the caller for atomic "
             "cache publication. Generated user credentials are temporary on Linux; CA issuance records remain.")
    lanes(p, [(240, "Linux caller", "launcher and cache writer", INK),
              (800, "Linux CRAFT worker", "dedicated craft service account", TEAL),
              (1400, "AD directory and PKI", "Global Catalog, CES, CA and KDC", BLUE)])
    p.number_badge(70, 325, 1, TEAL)
    p.message(245, 795, 325, "Absent home pair; start service-account worker", color=TEAL, size=22)
    p.number_badge(70, 395, 2, TEAL)
    p.message(805, 1400, 376, "GC / LDAP / GSSAPI: resolve caller UPN", color=TEAL, size=22)
    p.message(1400, 805, 415, "Unique AD user; keytab authenticates lookup", color=TEAL, dashed=True, size=21)
    p.number_badge(70, 484, 3, TEAL)
    p.rect(550, 449, 670, 79, TEAL_LIGHT, radius=9)
    p.lines(573,
        460,
        ["Generate RSA-3072 key and user CSR.",
        "Sign EOBO request with enrollment-agent key."],
        23,
        leading=31,
        max_width=622)
    p.number_badge(70, 593, 4, TEAL)
    p.message(805, 1400, 570, "CES / HTTPS: submit restricted EOBO request", color=TEAL, size=22)
    p.message(1400, 805, 615, "CA issues certificate with user SID and template", color=TEAL, dashed=True, size=22)
    p.number_badge(70, 682, 5, TEAL)
    p.rect(550, 653, 670, 69, TEAL_LIGHT, radius=9)
    p.lines(573,
        662,
        ["Validate key, UPN, template, EKUs and validity.",
        "Verify user-certificate CA chain and current CRLs."],
        22,
        leading=29,
        max_width=622)
    p.number_badge(70, 780, 6, BLUE)
    p.message(805, 1400, 757, "KDC / PKINIT: Linux username @ realm", color=BLUE, size=23)
    p.message(1400, 805, 804, "User TGT + session key; KDC decides grant", color=BLUE, dashed=True, size=23)
    p.number_badge(70, 869, 7, BLUE)
    p.message(795, 245, 869, "Validate TGT; return cache bytes to caller", color=BLUE, dashed=True, size=23)
    p.text(108, 912, (
        'Caller publishes .krb5cc_craft mode 0600. Temporary user key and '
        'certificate are released.'
    ), 23, INK, max_width=1428)
    p.footer("source/README.md: Mode 1 setup; docs/03-Enrollment-Agent-Restrictions.md")


def lanes(p, actors):
    for x, title, detail, color in actors:
        p.rect(x - 190, 214, 380, 66, WHITE, LINE, radius=9)
        p.text(x, 223, title, 25, color, "semibold", align="center")
        p.text(x, 256, detail, 18, MUTED, align="center")
        p.line([(x, 287), (x, 899)], LINE, 1.1, dashed=True)


def credential_linking(pdf):
    p = Page(pdf, "03-credential-linking-sequence", 3, "Mode 2  Privileged credential linking",
             (
                 'Linux links a temporary AD public key, performs Key Trust PKINIT, and '
                 'removes the entry before publishing the TGT.'
             ),
             "With both home PEM files absent and mechanism=key_trust, the setuid launcher starts the worker "
             "as the dedicated service account. The service keytab authenticates a GSSAPI LDAP bind to the same "
             "writable DC used as the KDC. CRAFT resolves the user, generates an RSA-2048 key and local certificate "
             "identity, adds one Key Credential to msDS-KeyCredentialLink, and performs Key Trust PKINIT. "
             "The independent cleanup process removes that exact entry before validated TGT bytes return. "
             "Existing keys are preserved. Failed cleanup blocks publication and can require manual removal.")
    lanes(p, [(240, "Linux caller", "launcher and cache writer", INK),
              (800, "Linux CRAFT worker", "dedicated craft service account", PURPLE),
              (1400, "Same writable DC", "LDAP directory and PKINIT KDC", BLUE)])
    p.number_badge(70, 325, 1, PURPLE)
    p.message(245, 795, 325, "Absent home pair; start service-account worker", color=PURPLE, size=22)
    p.number_badge(70, 395, 2, PURPLE)
    p.message(805, 1400, 376, "LDAP / GSSAPI: bind with service keytab", color=PURPLE, size=23)
    p.message(1400, 805, 415, "Resolve caller object and directory UPN", color=PURPLE, dashed=True, size=23)
    p.number_badge(70, 484, 3, PURPLE)
    p.rect(550, 449, 670, 79, WHITE, LINE, radius=9)
    p.lines(573,
        460,
        ["Generate RSA-2048 key and local certificate identity.",
        "Directory key matching authorizes the user."],
        22,
        leading=31,
        max_width=622)
    p.number_badge(70, 565, 4, PURPLE)
    p.message(805, 1400, 565, "Add one temporary msDS-KeyCredentialLink", color=PURPLE, size=23)
    p.number_badge(70, 663, 5, BLUE)
    p.message(805, 1400, 641, "Key Trust PKINIT: Linux username @ realm", color=BLUE, size=23)
    p.message(1400, 805, 689, "KDC matches linked key; user TGT returned", color=BLUE, dashed=True, size=23)
    p.number_badge(70, 767, 6, PURPLE)
    p.message(805, 1400, 748, "Validate TGT; remove exactly the added key", color=PURPLE, size=23)
    p.message(1400, 805, 792, "Removal confirmed; existing keys preserved", color=PURPLE, dashed=True, size=23)
    p.number_badge(70, 855, 7, BLUE)
    p.message(795, 245, 855, "Return validated cache bytes to caller", color=BLUE, dashed=True, size=23)
    p.lines(108, 901, ["Caller publishes .krb5cc_craft mode 0600. Cleanup also runs after acquisition failure.",
                       "Failed cleanup blocks publication and reports a residual key for administrator removal."],
            21, INK, leading=28, max_width=1428)
    p.footer("source/README.md: Mode 2 setup; docs/04-Key-Credential-Link-Delegation.md")


def timing(pdf):
    p = Page(pdf, "05-credential-timing", 5, "Ticket clocks and certificate storage",
             (
                 'All three modes request 10 h / 7 d by default. Certificate lifetime and '
                 'KDC policy constrain the initial grant.'
             ),
             "Home certificates and keys persist until the user replaces or removes them; ordinary certificate "
             "validity is accepted. Enrollment generates a temporary key and certificate, caps certificate "
             "validity at ten hours by default and releases its pair after PKINIT. All three modes request the same "
             "ten-hour TGT and seven-day renewal window. Renewal uses the cached ticket and session key. "
             "Fresh authentication near day six reuses a valid home pair, "
             "or uses the configured privileged mechanism if both files are absent. "
             "The renewed ticket's absolute renewal deadline remains fixed. Times are schedule illustrations.")
    for x, color, label, body in [
        (64, TEAL, "1 / ENROLLMENT", ["Temporary key and certificate.", "CA issuance records remain."]),
        (564,
            PURPLE,
            "2 / CREDENTIAL LINKING",
            ["Temporary key and local identity.",
            "Remove directory entry after PKINIT."]),
        (1064,
            BLUE,
            "3 / WINDOWS-EXPORTED PEM",
            ["Persistent supplied certificate and key.",
            "Replace the pair before expiry."]),
    ]:
        p.rect(x, 208, 472, 90, WHITE, LINE, radius=10)
        p.text(x + 20, 219, label, 18, color, "semibold")
        p.lines(x + 20, 246, body, 20, INK, leading=26, max_width=432)

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
    p.text(64, 776, "Acquisition 1", 22, INK, "semibold")
    p.text(64, 805, "Renewal window", 15, MUTED)
    p.rect(day(0), 773, day(7) - day(0), 42, BLUE_LIGHT, radius=6)
    p.rect(day(0), 773, day(6) - day(0), 42, BLUE, radius=6)
    p.text(day(0) + 18, 785, "Original renewal window", 18, WHITE, "semibold")
    p.text(day(7) - 10, 785, "Deadline", 17, BLUE, align="right")
    p.arrow([(day(6), 816), (day(6), 847)], TEAL, 2, head=7)
    p.text(day(6) + 13, 820, "Refresh ~day 6", 17, TEAL, "semibold")
    p.text(64, 852, "Acquisition 2", 22, INK, "semibold")
    p.text(64, 881, "Any of the three modes", 15, MUTED)
    p.polygon([(day(6), 849), (end - 15, 849), (end, 870), (end - 15, 891), (day(6), 891)], TEAL)
    p.text(day(6) + 18, 861, "New 7-day window", 18, WHITE, "semibold")
    p.text(1536, 902, "Continues to ~day 13", 15, MUTED, align="right")
    p.text(64, 929, "Renewal uses the cached ticket and session key. "
           "Certificate expiry or cleanup does not revoke an issued ticket.",
           17, INK, max_width=1472)
    p.footer("maintain.cpp: schedule, validate_renewed_tgt; worker.cpp: get_tgt; config.example: lifetime defaults")


def maintenance(pdf):
    p = Page(pdf, "06-job-maintenance", 6, "Keep a job authenticated, then stop with it.",
             "craft-maintain runs as the caller, coordinates one shared cache per UID, and watches a live process.",
             "The maintainer starts once for a watched job PID. A usable cache and detached loop are required "
             "before startup returns successfully. Due renewable TGTs renew at the KDC using the cached ticket "
             "and session key. Missing or expired TGTs, the rollover window, or nonextendible tickets near expiry "
             "trigger fresh authentication through craft, using a home pair first or the configured enrollment "
             "or credential-linking mode when absent. Due renewal takes priority over rollover. Successful "
             "updates atomically replace the cache. Renewal retains usable service tickets; fresh authentication "
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
    p.text(64, 482, "A renewal error retries; no immediate fresh authentication.", 16, MUTED, max_width=704)
    p.line([(790, 347), (790, 642)], LINE, 1)
    p.text(824, 349, "02 / FRESH AUTHENTICATION", 15, TEAL, "semibold")
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

    for x, w, title, detail in [(824, 178, "Run craft", "select source"),
                               (1062, 218, "Selected mode", "1, 2 or 3"),
                               (1340, 196, "KDC / PKINIT", "new user TGT")]:
        p.rect(x, 522, w, 79, TEAL_LIGHT, radius=9)
        p.text(x + w / 2, 536, title, 21, INK, "semibold", align="center")
        p.text(x + w / 2, 569, detail, 17, MUTED, align="center")
    p.arrow([(1002, 561), (1062, 561)], TEAL)
    p.arrow([(1280, 561), (1340, 561)], TEAL)
    p.lines(824, 615, ["Home PEM, enrollment or credential linking.", "New renewal window; replace cache."],
            18, TEAL, leading=24, max_width=710)
    p.text(64, 665, "A due renewal takes priority during rollover, "
           "keeping usable credentials alive while fresh authentication is delayed.",
           18, MUTED, max_width=1472)

    p.rect(64, 708, 1472, 92, WHITE, LINE, radius=11)
    p.text(84, 724, "Successful refresh", 22, INK, "semibold")
    p.text(84, 759, "Publish atomically to .krb5cc_craft (caller-owned, mode 0600).", 18, INK, max_width=684)
    p.line([(790, 725), (790, 782)], LINE, 1)
    p.text(824, 724, "Refresh failure", 22, INK, "semibold")
    p.text(824, 759, "Keep the existing cache and retry; the job continues.", 18, INK, max_width=692)

    notes = [
        (64, 460, "RETRY", ["Renewal: ~30 s to 5 min + jitter.", "Fresh acquisition: 1 min to 1 h cooldown."]),
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


def home_certificate(pdf):
    p = Page(pdf, "04-windows-exported-certificate", 4, "Mode 3  Unprivileged Windows-exported certificate",
             "Windows enrolls and exports the certificate. Linux uses the transferred PEM pair entirely as the caller.",
             "The domain user runs the Windows certificate helper without elevation to enroll a certificate "
             "with an exportable software key. It exports user.pem and unencrypted user.key. Both files are "
             "transferred securely to the Linux user's fixed NSS-home .config/craft directory. Ordinary "
             "CRAFT executables run as the caller, validate files and the certificate against root-controlled "
             "CA trust and current CRLs, and perform PKINIT for Linux username at the configured realm. "
             "The KDC maps the certificate; CRAFT validates and publishes the TGT. The supplied pair persists "
             "and requires replacement before expiry. No Linux service account, keytab, LDAP or CES is needed.")
    lanes(p, [(240, "Windows domain user", "direct user enrollment and export", BLUE),
              (800, "Linux user and CRAFT", "ordinary executables; caller UID", BLUE),
              (1400, "AD CS and KDC", "certificate issuance and PKINIT", TEAL)])
    p.number_badge(70, 343, 1, BLUE)
    p.message(245, 1400, 325, (
        'Windows enrollment policy: request a user certificate with an exportable'
        ' software key'
    ), color=TEAL, size=23)
    p.message(1400, 245, 371, (
        'AD CS issues the user certificate; private key stays with the user'
    ), color=TEAL, dashed=True, size=23)
    p.number_badge(70, 456, 2, BLUE)
    p.rect(130, 413, 620, 93, BLUE_LIGHT, radius=9)
    p.lines(152,
        427,
        ["Request-CRAFT-Certificate.cmd exports",
        "user.pem + matching unencrypted user.key"],
        23,
        leading=33,
        max_width=574)
    p.number_badge(70, 551, 3, BLUE)
    p.message(245, 795, 551, "Securely transfer both PEM files to Linux", color=BLUE, size=23)
    p.number_badge(70, 638, 4, BLUE)
    p.rect(550, 589, 720, 103, BLUE_LIGHT, radius=9)
    p.lines(573, 601, ["Install at NSS home: ~/.config/craft/user.pem + user.key",
                        "Run craft as the user; check files and certificate.",
                        "Validate CA chain and CRLs; use public /etc/craft policy."], 21, leading=30, max_width=674)
    p.number_badge(70, 757, 5, BLUE)
    p.message(805, 1400, 734, "KDC / PKINIT: Linux username @ realm", color=BLUE, size=23)
    p.message(1400, 805, 781, "KDC maps certificate and returns user TGT", color=BLUE, dashed=True, size=23)
    p.number_badge(70, 860, 6, BLUE)
    p.rect(550, 817, 720, 93, BLUE_LIGHT, radius=9)
    p.lines(573, 831, ["Validate returned TGT; publish mode-0600 .krb5cc_craft.",
                        "PEM files remain; replace the pair before expiry."], 23, leading=33, max_width=674)
    p.text(108, 925, (
        'No Linux setuid bit, service account, directory keytab, LDAP lookup, CES'
        ' or /run/craft.'
    ), 22, INK, max_width=1428)
    p.footer("source/README.md: Mode 3 setup; scripts/Request-CRAFT-Certificate.cmd")


def main():
    fonts()
    SVG_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = ROOT / "CRAFT-Diagrams.pdf"
    pdf = canvas.Canvas(str(pdf_path), pagesize=(WIDTH * SCALE, HEIGHT * SCALE), pageCompression=1)
    pdf.setTitle("CRAFT operating modes and ticket lifecycle")
    pdf.setAuthor("CRAFT")
    pdf.setSubject((
        'Privileged enrollment, privileged credential linking, unprivileged '
        'Windows PEM, renewal and maintenance'
    ))
    pdf.setCreator("CRAFT vector diagram builder")
    diagrams = (overview, acquisition, credential_linking, home_certificate, timing, maintenance)
    for page in diagrams:
        page(pdf)
    pdf.save()
    print(f"Created {pdf_path} and {len(diagrams)} matching SVG diagrams in {SVG_DIR}")


if __name__ == "__main__":
    main()
