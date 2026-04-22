"""
interface.py  —  BitLocker Key Finder v1.0
FAST-NUCES Islamabad  |  Digital Forensics  |  Semester 6

Changes v2:
  1.  Only Professional Theme (no hacker, no theme selector)
  2.  Splash = full-screen "Press Enter" screen (resizable)
  3.  Buttons repositioned and clearly visible
  4.  Min / Max file size filter in scan options
  5.  Found-key detail popup shows only relevant forensic fields
  6.  Copy-to-clipboard removed; Save-to-file only
  7.  PDF export with Semester 6 header, team names, timestamp, keys table
  8.  Export goes to user-selected folder (default = script directory)
  9.  RAM screen has its own isolated styling dict (RAM_T)
"""

import os
import shutil
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from modules.partition_scan import scan_partition, save_report
from modules.pdf_reporter import generate_partition_report  # NEW - PDF export
from ui.ram_interface import RamScreen  # Part A — full RAM extraction screen
from ui.settings_screens import SettingsScreen, HelpScreen, AboutScreen  # NEW
from ui.case_dialog import CaseInfoDialog  # NEW - Case info dialog
import theme_config  # NEW - Import global theme config

# ══════════════════════════════════════════════════════════════════════════════
#  PROJECT INFO
# ══════════════════════════════════════════════════════════════════════════════
PROJECT_INFO = {
    "title":   "BitLocker Key Finder",
    "version": "v1.0",
    "subject": "Digital Forensics",
    "uni":     "FAST-NUCES Islamabad",
    "members": [
        ("Irtaza Zahid",   "23i-2096"),
        ("Ammar Shahid",   "23I-2125"),
        ("Usman Khan",     "23I-2069"),
        ("Shaheer Shaban", "23I-2040"),
    ],
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ══════════════════════════════════════════════════════════════════════════════
#  PROFESSIONAL THEME  (from theme_config - changes globally)
# ══════════════════════════════════════════════════════════════════════════════
# Get current theme from global config
T = theme_config.get_current_theme()

# ══════════════════════════════════════════════════════════════════════════════
#  RAM SCREEN THEME  (Option 1) — terminal / memory-forensics aesthetic
#  Deliberately distinct from the Scan theme:
#     • Pure-black background + amber monospace (old VT-terminal look)
#     • No rounded cards, no Segoe UI
#     • Character-grid feel using Consolas everywhere
#  Ensures operator is never confused about which subsystem is active.
# ══════════════════════════════════════════════════════════════════════════════
RAM_T = {
    "BG":           "#000000",
    "BG_CARD":      "#0a0a0a",
    "BG_ALT":       "#111111",
    "ACCENT":       "#ff9500",   # terminal amber
    "ACCENT2":      "#00ff88",   # phosphor green (success)
    "ACCENT3":      "#ff3b30",   # alert red
    "TEXT":         "#e0e0e0",
    "TEXT_DIM":     "#606060",
    "BORDER":       "#2a2a2a",
    "FONT_TITLE":   ("Consolas", 24, "bold"),
    "FONT_HEADER":  ("Consolas", 12, "bold"),
    "FONT_BODY":    ("Consolas", 11),
    "FONT_SMALL":   ("Consolas", 9),
}

# ══════════════════════════════════════════════════════════════════════════════
#  FILE EXTENSIONS
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_EXTENSIONS = [
    ".txt", ".bek", ".csv", ".docx", ".xlsx", ".pdf", ".rtf",
]
EXTRA_EXTENSIONS = [
    ".log", ".md", ".ini", ".cfg", ".conf", ".bat", ".ps1",
    ".json", ".xml", ".html", ".htm", ".yaml", ".yml",
    ".key", ".asc", ".pem", ".crt", ".cer", ".sql",
    ".py", ".js", ".ts", ".reg", ".tsv",
    ".pptx", ".odt", ".ods", ".odp", ".eml",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif",
    ".db", ".sqlite", ".mdb", ".accdb",
    ".dat", ".bin", ".img", ".iso", ".vhd", ".vmdk",
]


# ══════════════════════════════════════════════════════════════════════════════
#  EXPORTS  (PDF + CSV)
# ══════════════════════════════════════════════════════════════════════════════
def export_csv(results, output_folder):
    """Export results to CSV with all forensic fields."""
    import csv as _csv
    os.makedirs(output_folder, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_folder, f"BitLocker_Report_{ts}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = _csv.writer(f)
        writer.writerow(["#", "Validation", "BitLocker Key",
                         "Recovery Key ID", "Source", "File Path"])
        for i, row in enumerate(results, 1):
            writer.writerow([
                i,
                row.get("Validation", "N/A"),
                row.get("BitLocker Key", ""),
                row.get("Recovery Key ID", ""),
                row.get("Source", ""),
                row.get("File Path", ""),
            ])
    return path


def export_pdf(results, output_folder):
    """Generate a professional PDF report with team header and key table."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        now = datetime.datetime.now()
        ts  = now.strftime("%Y%m%d_%H%M%S")
        filename = f"BitLocker_Report_{ts}.pdf"
        filepath = os.path.join(output_folder, filename)

        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            topMargin=1.8*cm, bottomMargin=1.8*cm,
            leftMargin=2*cm, rightMargin=2*cm
        )

        styles = getSampleStyleSheet()
        navy   = colors.HexColor("#1c2340")
        blue   = colors.HexColor("#4fc3f7")
        green  = colors.HexColor("#69db7c")
        amber  = colors.HexColor("#ffa94d")
        light  = colors.HexColor("#dce3f0")
        dim    = colors.HexColor("#8899aa")
        dark   = colors.HexColor("#0d1020")

        title_style = ParagraphStyle(
            "Title2", parent=styles["Normal"],
            fontSize=20, fontName="Helvetica-Bold",
            textColor=blue, alignment=TA_CENTER, spaceAfter=4
        )
        sub_style = ParagraphStyle(
            "Sub", parent=styles["Normal"],
            fontSize=11, fontName="Helvetica",
            textColor=light, alignment=TA_CENTER, spaceAfter=2
        )
        label_style = ParagraphStyle(
            "Label", parent=styles["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=dim, alignment=TA_CENTER, spaceAfter=12
        )
        section_style = ParagraphStyle(
            "Section", parent=styles["Normal"],
            fontSize=11, fontName="Helvetica-Bold",
            textColor=amber, spaceAfter=6, spaceBefore=14
        )
        body_style = ParagraphStyle(
            "Body2", parent=styles["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=light, spaceAfter=4
        )
        key_style = ParagraphStyle(
            "Key", parent=styles["Normal"],
            fontSize=8, fontName="Courier",
            textColor=green, spaceAfter=2
        )

        story = []

        # ── Header block ──────────────────────────────────────────────────────
        story.append(Paragraph("BitLocker Key Finder", title_style))
        story.append(Paragraph(f"{PROJECT_INFO['title']}  —  {PROJECT_INFO['version']}", sub_style))
        story.append(Paragraph(
            f"{PROJECT_INFO['uni']}  ·  {PROJECT_INFO['subject']}  ·  Semester 6",
            label_style
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=blue, spaceAfter=6))

        # Team members table
        members_data = [["#", "Name", "Roll Number"]]
        for i, (name, roll) in enumerate(PROJECT_INFO["members"], 1):
            members_data.append([str(i), name, roll])

        mem_table = Table(members_data, colWidths=[1*cm, 8*cm, 5*cm])
        mem_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  navy),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  blue),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0),  9),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("BACKGROUND",  (0, 1), (-1, -1), colors.HexColor("#1a2038")),
            ("TEXTCOLOR",   (0, 1), (-1, -1), light),
            ("FONTSIZE",    (0, 1), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#1a2038"), colors.HexColor("#232b4a")]),
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#2e3a5c")),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(mem_table)
        story.append(Spacer(1, 10))

        # Scan metadata
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#2e3a5c"), spaceAfter=8))
        story.append(Paragraph("Scan Information", section_style))

        meta = [
            ["Generated",    now.strftime("%Y-%m-%d  %H:%M:%S")],
            ["Keys Found",   str(len(results))],
            ["Tool Version", PROJECT_INFO["version"]],
        ]
        meta_table = Table(meta, colWidths=[4*cm, 13*cm])
        meta_table.setStyle(TableStyle([
            ("TEXTCOLOR",   (0, 0), (0, -1), amber),
            ("TEXTCOLOR",   (1, 0), (1, -1), light),
            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("TOPPADDING",  (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # Keys table
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#2e3a5c"), spaceAfter=8))
        story.append(Paragraph(f"Found BitLocker Keys  ({len(results)} total)", section_style))

        if results:
            tdata = [["#", "Validation", "BitLocker Recovery Key",
                      "Recovery Key ID", "Source"]]
            for i, row in enumerate(results, 1):
                tdata.append([
                    str(i),
                    row.get("Validation", "N/A"),
                    row.get("BitLocker Key", ""),
                    row.get("Recovery Key ID", ""),
                    row.get("Source", ""),
                ])

            keys_table = Table(tdata,
                               colWidths=[0.7*cm, 2.6*cm, 7.2*cm, 4.3*cm, 2.6*cm])
            keys_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0),  navy),
                ("TEXTCOLOR",    (0, 0), (-1, 0),  blue),
                ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, 0),  8),
                ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME",     (0, 1), (-1, -1), "Courier"),
                ("FONTSIZE",     (0, 1), (-1, -1), 7),
                ("TEXTCOLOR",    (2, 1), (2, -1),  green),
                ("TEXTCOLOR",    (3, 1), (3, -1),  colors.HexColor("#a78bfa")),
                ("TEXTCOLOR",    (0, 1), (0, -1),  dim),
                ("TEXTCOLOR",    (1, 1), (1, -1),  amber),
                ("TEXTCOLOR",    (4, 1), (4, -1),  light),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#1a2038"), colors.HexColor("#232b4a")]),
                ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#2e3a5c")),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("WORDWRAP",     (2, 1), (2, -1),  True),
            ]))
            story.append(keys_table)
            story.append(Spacer(1, 14))

            # Per-key: file path + full raw file content
            story.append(Paragraph("Key File Details &amp; Raw Content", section_style))
            for i, row in enumerate(results, 1):
                fpath   = row.get("File Path", "")
                bkey    = row.get("BitLocker Key", "N/A")
                rid     = row.get("Recovery Key ID", "N/A")
                source  = row.get("Source", "N/A")
                valid   = row.get("Validation", "N/A")

                story.append(Paragraph(
                    f"[{i}]  Key: <b>{bkey}</b>",
                    key_style
                ))
                story.append(Paragraph(
                    f"     Validation: <b>{valid}</b>   |   "
                    f"ID: {rid}   |   Source: {source}",
                    body_style
                ))
                story.append(Paragraph(
                    f"     File: {fpath}",
                    body_style
                ))

                # Read and embed actual file content
                raw_content = _read_file_content(fpath)
                # Truncate very long files for PDF
                if len(raw_content) > 3000:
                    raw_content = raw_content[:3000] + "\n... [truncated]"

                # Escape XML special chars for reportlab
                raw_safe = (raw_content
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;"))

                file_content_style = ParagraphStyle(
                    f"FC{i}", parent=styles["Normal"],
                    fontSize=7, fontName="Courier",
                    textColor=colors.HexColor("#a0b0c0"),
                    spaceAfter=4, spaceBefore=2,
                    leftIndent=14,
                    borderPad=6,
                    backColor=colors.HexColor("#0d1020"),
                )
                story.append(Paragraph(raw_safe.replace("\n", "<br/>"),
                                       file_content_style))
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No BitLocker keys were found in this scan.", body_style))

        # Footer note
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#2e3a5c"), spaceAfter=6))
        story.append(Paragraph(
            f"This report was generated by {PROJECT_INFO['title']} {PROJECT_INFO['version']}  "
            f"·  {PROJECT_INFO['uni']}  ·  {PROJECT_INFO['subject']}  ·  Semester 6  "
            f"·  {now.strftime('%Y-%m-%d %H:%M:%S')}",
            label_style
        ))

        doc.build(story)
        return filepath

    except ImportError:
        # Fallback to CSV if reportlab not installed
        return save_report(results, output_folder)
    except Exception as e:
        raise RuntimeError(f"PDF export failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER: styled button
# ══════════════════════════════════════════════════════════════════════════════
def make_btn(parent, text, cmd, fg_color, theme=None, **kw):
    th = theme or T
    padx = kw.pop("padx", 14)
    pady = kw.pop("pady", 7)
    font = kw.pop("font", th["FONT_BODY"])
    btn = tk.Button(
        parent, text=text, command=cmd,
        bg=th["BG_CARD"], fg=fg_color,
        activebackground=fg_color, activeforeground=th.get("BG_DARK", th["BG_CARD"]),
        font=font, relief=tk.FLAT, bd=0, cursor="hand2",
        padx=padx, pady=pady,
        highlightthickness=1, highlightbackground=fg_color,
        **kw
    )

    def _enter(e): btn.config(bg=fg_color, fg=th.get("BG_DARK", "#000000"))
    def _leave(e): btn.config(bg=th["BG_CARD"], fg=fg_color)
    btn.bind("<Enter>", _enter)
    btn.bind("<Leave>", _leave)
    return btn


# ══════════════════════════════════════════════════════════════════════════════
#  SPLASH / WELCOME SCREEN  (full screen, press Enter to continue)
# ══════════════════════════════════════════════════════════════════════════════
class SplashScreen:
    def __init__(self, master, on_continue):
        self.master      = master
        self.on_continue = on_continue
        self._blink_on   = True
        self._build()

    def _build(self):
        self.master.title("BitLocker Key Finder v1.0")
        # Full screen / maximized
        try:
            self.master.state("zoomed")      # Windows maximize
        except Exception:
            self.master.attributes("-zoomed", True)  # Linux fallback
        self.master.resizable(True, True)
        self.master.configure(bg=T["BG_DARK"])

        # Outer frame — centers content vertically & horizontally
        outer = tk.Frame(self.master, bg=T["BG_DARK"])
        outer.place(relx=0.5, rely=0.5, anchor="center")

        # Top accent bar
        tk.Frame(outer, bg=T["ACCENT1"], height=3, width=700).pack()

        tk.Label(
            outer,
            text=f"  {PROJECT_INFO['title'].upper()}  ",
            font=("Segoe UI", 36, "bold"),
            bg=T["BG_DARK"], fg=T["ACCENT1"]
        ).pack(pady=(18, 2))

        tk.Label(
            outer,
            text=f"Version  {PROJECT_INFO['version']}",
            font=("Segoe UI", 14),
            bg=T["BG_DARK"], fg=T["ACCENT2"]
        ).pack(pady=(0, 16))

        tk.Frame(outer, bg=T["BORDER"], height=1, width=680).pack(pady=4)

        tk.Label(
            outer,
            text=f"{PROJECT_INFO['uni']}   ◈   {PROJECT_INFO['subject']}   ◈   Semester 6",
            font=("Segoe UI", 12),
            bg=T["BG_DARK"], fg=T["TEXT_LABEL"]
        ).pack(pady=10)

        # Members grid — 2 columns
        mf = tk.Frame(outer, bg=T["BG_DARK"])
        mf.pack(pady=6)
        for i, (name, roll) in enumerate(PROJECT_INFO["members"]):
            tk.Label(
                mf,
                text=f"  ›  {name}   [{roll}]  ",
                font=("Segoe UI", 11),
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"]
            ).grid(row=i // 2, column=i % 2, sticky="w", padx=30, pady=3)

        tk.Frame(outer, bg=T["BORDER"], height=1, width=680).pack(pady=14)

        # Blinking label
        self.blink_lbl = tk.Label(
            outer,
            text="[ PRESS  ENTER  OR  CLICK  TO  START ]",
            font=("Segoe UI", 13, "bold"),
            bg=T["BG_DARK"], fg=T["ACCENT1"]
        )
        self.blink_lbl.pack(pady=8)

        # Bottom accent bar
        tk.Frame(outer, bg=T["ACCENT1"], height=3, width=700).pack(pady=(14, 0))

        self.master.bind("<Return>",   lambda e: self._go())
        self.master.bind("<space>",    lambda e: self._go())
        self.master.bind("<Button-1>", lambda e: self._go())
        self._blink()

    def _blink(self):
        try:
            self.blink_lbl.config(fg=T["ACCENT1"] if self._blink_on else T["BG_DARK"])
            self._blink_on = not self._blink_on
            self.master.after(600, self._blink)
        except Exception:
            pass  # widget destroyed — stop blinking silently

    def _go(self):
        self.master.unbind("<Return>")
        self.master.unbind("<space>")
        self.master.unbind("<Button-1>")
        self.on_continue()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════
class MainMenu:
    def __init__(self, master, on_select):
        self.master    = master
        self.on_select = on_select
        self._build()

    def _build(self):
        global T
        for w in self.master.winfo_children():
            w.destroy()

        # Refresh theme from global config
        T = theme_config.get_current_theme()

        try:
            self.master.state("zoomed")
        except Exception:
            pass
        self.master.resizable(True, True)
        self.master.configure(bg=T["BG_DARK"])

        # Top bar
        bar = tk.Frame(self.master, bg=T["BG_PANEL"])
        bar.pack(fill="x")
        tk.Label(
            bar,
            text=f"  🔑  {PROJECT_INFO['title'].upper()}   {PROJECT_INFO['version']}",
            font=T["FONT_TITLE"], bg=T["BG_PANEL"], fg=T["ACCENT1"],
            pady=14
        ).pack(side="left", padx=14)
        tk.Label(
            bar,
            text=f"{PROJECT_INFO['uni']}  |  {PROJECT_INFO['subject']}",
            font=T["FONT_SMALL"], bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
            pady=14
        ).pack(side="right", padx=16)
        tk.Frame(self.master, bg=T["ACCENT1"], height=2).pack(fill="x")

        # Center frame
        center = tk.Frame(self.master, bg=T["BG_DARK"])
        center.place(relx=0.5, rely=0.48, anchor="center")

        tk.Label(
            center, text="═══   SELECT  MODE   ═══",
            font=T["FONT_HEADER"], bg=T["BG_DARK"], fg=T["TEXT_DIM"],
            pady=20
        ).pack()

        menu_items = [
            (1, "1", "⚡   LIVE RAM EXTRACTION",
             "Extract BitLocker keys directly from live system memory\n"
             "Requires Administrator privileges  |  Phase 2 — Coming Soon",
             T["ACCENT3"]),
            (2, "2", "🔍   PARTITION / DISK SCAN",
             "Search any drive, folder or partition for BitLocker recovery keys\n"
             "Supports 35+ file types  |  PDF, DOCX, XLSX, TXT, BEK and more",
             T["ACCENT1"]),
            (3, "3", "⚙️    SETTINGS",
             "Configure theme and validation settings",
             T["ACCENT1"]),
            (4, "4", "❓   HELP & DOCUMENTATION",
             "User guide, quick start, FAQ, and BitLocker basics",
             T["ACCENT1"]),
            (5, "5", "ℹ️    ABOUT",
             "About this tool, team information, and contact details",
             T["ACCENT1"]),
            (6, "6", "✕    EXIT",
             "Close the application",
             T["ACCENT4"]),
        ]

        for choice, num, title, desc, color in menu_items:
            self._card(center, choice, num, title, desc, color)

        # Footer
        tk.Frame(self.master, bg=T["BORDER"], height=1).pack(fill="x", side="bottom")
        footer = tk.Frame(self.master, bg=T["BG_PANEL"])
        footer.pack(fill="x", side="bottom")
        members_str = "   ◈   ".join(f"{n} [{r}]" for n, r in PROJECT_INFO["members"])
        tk.Label(
            footer,
            text=f"  {members_str}  ",
            font=T["FONT_SMALL"], bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
            pady=7
        ).pack()

        self.master.bind("1", lambda e: self.on_select(1))
        self.master.bind("2", lambda e: self.on_select(2))
        self.master.bind("3", lambda e: self.on_select(3))

    def _card(self, parent, choice, num, title, desc, color):
        card  = tk.Frame(parent, bg=T["BG_CARD"], cursor="hand2", width=720)
        card.pack(pady=5)
        card.pack_propagate(False)
        card.config(height=80)

        inner = tk.Frame(card, bg=T["BG_CARD"])
        inner.pack(fill="both", expand=True, padx=16, pady=10)

        badge = tk.Label(inner, text=f"  {num}  ",
                         font=("Segoe UI", 18, "bold"),
                         bg=color, fg=T["BG_DARK"], padx=8, pady=2)
        badge.pack(side="left", padx=(0, 16))

        txt = tk.Frame(inner, bg=T["BG_CARD"])
        txt.pack(side="left", fill="x", expand=True)

        lbl_t = tk.Label(txt, text=title, font=T["FONT_HEADER"],
                         bg=T["BG_CARD"], fg=color, anchor="w")
        lbl_t.pack(anchor="w")
        lbl_d = tk.Label(txt, text=desc, font=T["FONT_SMALL"],
                         bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                         anchor="w", justify="left")
        lbl_d.pack(anchor="w")

        all_w = [card, inner, badge, txt, lbl_t, lbl_d]

        def _enter(e):
            for w in all_w:
                try: w.config(bg=color)
                except Exception: pass
            badge.config(bg=T["BG_DARK"], fg=color)
            lbl_t.config(fg=T["BG_DARK"])
            lbl_d.config(fg=T["BG_DARK"])

        def _leave(e):
            for w in all_w:
                try: w.config(bg=T["BG_CARD"])
                except Exception: pass
            badge.config(bg=color, fg=T["BG_DARK"])
            lbl_t.config(fg=color)
            lbl_d.config(fg=T["TEXT_DIM"])

        def _click(e, c=choice):
            self.on_select(c)

        for w in all_w:
            w.bind("<Enter>",    _enter)
            w.bind("<Leave>",    _leave)
            w.bind("<Button-1>", _click)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _read_file_content(filepath):
    """Read a file and return its full text content. Tries multiple encodings."""
    if not filepath or not os.path.isfile(filepath):
        return f"[File not found: {filepath}]"
    try:
        size = os.path.getsize(filepath)
        if size > 5 * 1024 * 1024:
            return f"[File too large to display: {size // 1024} KB]\nPath: {filepath}"
        for enc in ["utf-16", "utf-16-le", "utf-8", "latin-1"]:
            try:
                with open(filepath, "r", encoding=enc, errors="strict") as f:
                    return f.read()
            except (UnicodeDecodeError, UnicodeError):
                continue
        # last resort
        with open(filepath, "r", encoding="latin-1", errors="replace") as f:
            return f.read()
    except PermissionError:
        return f"[Permission Denied: {filepath}]"
    except Exception as e:
        return f"[Error reading file: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
#  KEY DETAIL POPUP
# ══════════════════════════════════════════════════════════════════════════════
class KeyDetailPopup:
    """
    Shows the FULL raw text content of the source file.
    Only buttons: Copy (copies file content) and Close.
    """

    def __init__(self, master, row_data):
        self.win = tk.Toplevel(master)
        self.win.title("Key Details — Full File Content")
        self.win.configure(bg=T["BG_DARK"])
        self.win.geometry("860x560")
        self.win.resizable(True, True)
        self.row      = row_data
        self.filepath = row_data.get("File Path", "")
        self.content  = _read_file_content(self.filepath)
        self._build()

    def _build(self):
        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self.win, bg=T["BG_PANEL"])
        hdr.pack(fill="x")

        valid = self.row.get("Validation", "N/A")
        if valid.startswith("Valid"):
            v_col = T["ACCENT2"]; v_badge = "✓ VALID"
        elif valid.startswith("Pattern"):
            v_col = T["ACCENT3"]; v_badge = "⚠ PATTERN ONLY"
        else:
            v_col = T["TEXT_DIM"]; v_badge = valid

        tk.Label(
            hdr, text="  🔑   KEY FILE CONTENT",
            font=T["FONT_HEADER"], bg=T["BG_PANEL"],
            fg=T["ACCENT1"], pady=10
        ).pack(side="left", padx=10)

        tk.Label(
            hdr, text=f"  [ {v_badge} ]  ",
            font=("Consolas", 10, "bold"), bg=T["BG_PANEL"],
            fg=v_col
        ).pack(side="left", padx=2)

        # Copy + Close buttons in header top-right
        btn_f = tk.Frame(hdr, bg=T["BG_PANEL"])
        btn_f.pack(side="right", padx=10, pady=6)

        make_btn(btn_f, "📋  Copy Content", self._copy_content,
                 T["ACCENT2"], padx=12, pady=5,
                 font=T["FONT_SMALL"]).pack(side="left", padx=4)

        make_btn(btn_f, "✕  Close", self.win.destroy,
                 T["ACCENT4"], padx=12, pady=5,
                 font=T["FONT_SMALL"]).pack(side="left", padx=4)

        tk.Frame(self.win, bg=T["ACCENT1"], height=2).pack(fill="x")

        # ── File path info bar ───────────────────────────────────────────────
        info_bar = tk.Frame(self.win, bg=T["BG_CARD"], padx=12, pady=6)
        info_bar.pack(fill="x")

        tk.Label(
            info_bar, text="File Location:",
            font=("Segoe UI", 9, "bold"),
            bg=T["BG_CARD"], fg=T["TEXT_LABEL"]
        ).pack(side="left")

        tk.Label(
            info_bar,
            text=f"  {self.filepath}",
            font=("Consolas", 9),
            bg=T["BG_CARD"], fg=T["ACCENT3"],
            anchor="w"
        ).pack(side="left")

        tk.Frame(self.win, bg=T["BORDER"], height=1).pack(fill="x")

        # ── Full file content text box ───────────────────────────────────────
        text_frame = tk.Frame(self.win, bg=T["BG_DARK"])
        text_frame.pack(fill="both", expand=True, padx=0, pady=0)

        self.text_box = tk.Text(
            text_frame,
            bg="#0d1020", fg=T["ACCENT2"],
            font=("Consolas", 11),
            relief=tk.FLAT, bd=0,
            wrap="word",
            insertbackground=T["ACCENT1"],
            selectbackground=T["ACCENT1"],
            selectforeground=T["BG_DARK"],
            padx=20, pady=14,
            state=tk.NORMAL
        )
        vsb = ttk.Scrollbar(text_frame, command=self.text_box.yview)
        self.text_box.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.text_box.pack(side="left", fill="both", expand=True)

        # Insert content
        self.text_box.insert("1.0", self.content)
        self.text_box.config(state=tk.DISABLED)  # read-only

        # ── Bottom status bar ────────────────────────────────────────────────
        status = tk.Frame(self.win, bg=T["BG_PANEL"], height=24)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)

        lines = self.content.count("\n") + 1
        chars = len(self.content)
        tk.Label(
            status,
            text=f"  {lines} lines  ·  {chars} characters  ·  Source: {self.row.get('Source', 'N/A')}",
            bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
            font=("Consolas", 8)
        ).pack(side="left", padx=6)

    def _copy_content(self):
        self.win.clipboard_clear()
        self.win.clipboard_append(self.content)
        self.win.update()
        messagebox.showinfo("Copied",
                            "Full file content copied to clipboard!",
                            parent=self.win)


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN SCREEN
# ══════════════════════════════════════════════════════════════════════════════
class ScanScreen:
    def __init__(self, master, on_back):
        self.master    = master
        self.on_back   = on_back
        self.results   = []
        self.stop_flag = threading.Event()
        self.scanning  = False
        self.ext_vars  = {}
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────────
    def _build(self):
        for w in self.master.winfo_children():
            w.destroy()
        try:
            self.master.state("zoomed")
        except Exception:
            pass
        self.master.resizable(True, True)
        self.master.configure(bg=T["BG_DARK"])

        self._topbar()
        self._body()
        self._footer()
        self.master.bind("<Escape>", lambda e: self._go_back())
        self._tick_clock()

    def _topbar(self):
        bar = tk.Frame(self.master, bg=T["BG_PANEL"])
        bar.pack(fill="x")

        tk.Label(
            bar,
            text=f"  🔍  PARTITION / DISK SCAN  —  {PROJECT_INFO['title']} {PROJECT_INFO['version']}",
            font=T["FONT_HEADER"], bg=T["BG_PANEL"], fg=T["ACCENT1"], pady=8
        ).pack(side="left", padx=8)

        # ALL action buttons in top bar so they are always visible
        btn_frame = tk.Frame(bar, bg=T["BG_PANEL"])
        btn_frame.pack(side="right", padx=8, pady=5)

        make_btn(btn_frame, "◄ MENU", self._go_back, T["ACCENT3"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        tk.Frame(btn_frame, bg=T["BORDER"], width=1).pack(
            side="left", fill="y", padx=6, pady=4)

        self.scan_btn = tk.Button(
            btn_frame, text="▶  START SCAN", command=self._start_scan,
            bg=T["ACCENT2"], fg=T["BG_DARK"],
            activebackground="#4caf50", activeforeground=T["BG_DARK"],
            font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0,
            cursor="hand2", padx=14, pady=6,
        )
        self.scan_btn.pack(side="left", padx=3)

        self.stop_btn = tk.Button(
            btn_frame, text="■  STOP", command=self._stop_scan,
            bg=T["ACCENT4"], fg="white",
            activebackground="#c0392b", activeforeground="white",
            font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0,
            cursor="hand2", padx=10, pady=6, state=tk.DISABLED,
        )
        self.stop_btn.pack(side="left", padx=3)

        make_btn(btn_frame, "📄 EXPORT", self._export_pdf, T["ACCENT3"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        make_btn(btn_frame, "🗑 CLEAR", self._clear_all, T["TEXT_DIM"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        tk.Frame(self.master, bg=T["ACCENT1"], height=2).pack(fill="x")

    def _body(self):
        body = tk.Frame(self.master, bg=T["BG_DARK"])
        body.pack(fill="both", expand=True, padx=8, pady=6)

        # LEFT PANEL — scrollable canvas so nothing gets cut off
        left_outer = tk.Frame(body, bg=T["BG_DARK"], width=490)
        left_outer.pack(side="left", fill="y", padx=(0, 6))
        left_outer.pack_propagate(False)

        left_canvas = tk.Canvas(left_outer, bg=T["BG_DARK"],
                                highlightthickness=0, width=475)
        left_sb = ttk.Scrollbar(left_outer, orient="vertical",
                                command=left_canvas.yview)
        left_canvas.configure(yscrollcommand=left_sb.set)
        left_sb.pack(side="right", fill="y")
        left_canvas.pack(side="left", fill="both", expand=True)

        left = tk.Frame(left_canvas, bg=T["BG_DARK"])
        left_window = left_canvas.create_window((0, 0), window=left, anchor="nw")

        def _on_left_configure(e):
            left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        left.bind("<Configure>", _on_left_configure)

        def _on_canvas_resize(e):
            left_canvas.itemconfig(left_window, width=e.width)
        left_canvas.bind("<Configure>", _on_canvas_resize)

        # Mousewheel scroll on left panel
        def _on_mousewheel(e):
            left_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        left_canvas.bind("<MouseWheel>", _on_mousewheel)
        left.bind("<MouseWheel>", _on_mousewheel)

        self._source_card(left)
        self._options_card(left)
        self._size_filter_card(left)
        self._ext_card(left)
        self._output_card(left)
        self._stats_card(left)

        # RIGHT PANEL
        right = tk.Frame(body, bg=T["BG_DARK"])
        right.pack(side="left", fill="both", expand=True)
        self._console_panel(right)
        self._table_panel(right)

    def _footer(self):
        f = tk.Frame(self.master, bg=T["BG_PANEL"], height=26)
        f.pack(fill="x", side="bottom")
        f.pack_propagate(False)
        members_str = "  |  ".join(f"{n} [{r}]" for n, r in PROJECT_INFO["members"])
        tk.Label(f, text=f"  {PROJECT_INFO['uni']}  ◈  {members_str}",
                 bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
                 font=T["FONT_SMALL"]).pack(side="left", padx=8)
        self.clock_lbl = tk.Label(f, text="", bg=T["BG_PANEL"],
                                  fg=T["TEXT_DIM"], font=T["FONT_SMALL"])
        self.clock_lbl.pack(side="right", padx=10)

    def _tick_clock(self):
        self.clock_lbl.config(
            text=datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.master.after(1000, self._tick_clock)

    # ── Cards ──────────────────────────────────────────────────────────────────
    def _source_card(self, p):
        self._sec(p, "◈   TARGET DRIVE / FOLDER")
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", pady=(0, 4), padx=2)

        tk.Label(card, text="Path to scan:", bg=T["BG_CARD"],
                 fg=T["TEXT_LABEL"], font=T["FONT_SMALL"]).pack(anchor="w")

        row = tk.Frame(card, bg=T["BG_CARD"])
        row.pack(fill="x", pady=(3, 6))
        self.source_var = tk.StringVar()
        tk.Entry(row, textvariable=self.source_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=5
                 ).pack(side="left", fill="x", expand=True)
        make_btn(row, "Browse", self._browse_src, T["ACCENT1"],
                 padx=10, pady=5, font=T["FONT_SMALL"]).pack(side="left", padx=(4, 0))

        tk.Label(card, text="Quick drive select:", bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"], font=T["FONT_SMALL"]).pack(anchor="w")
        dr = tk.Frame(card, bg=T["BG_CARD"])
        dr.pack(fill="x")
        import string
        for d in string.ascii_uppercase:
            path = f"{d}:\\"
            if os.path.exists(path):
                make_btn(dr, f"{d}:",
                         lambda p=path: self.source_var.set(p),
                         T["ACCENT5"],
                         padx=8, pady=3, font=T["FONT_SMALL"]
                         ).pack(side="left", padx=2, pady=2)

    def _options_card(self, p):
        self._sec(p, "◈   SCAN OPTIONS")
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", pady=(0, 4), padx=2)

        self.opt_name    = tk.BooleanVar(value=True)
        self.opt_content = tk.BooleanVar(value=True)
        self.opt_carve   = tk.BooleanVar(value=False)
        self.opt_copy    = tk.BooleanVar(value=False)

        opts = [
            (self.opt_name,    "⚡  File Name Search",
             "Finds BitLocker-named files instantly  [FAST]"),
            (self.opt_content, "🔍  Deep Content Scan",
             "Reads & parses all selected extensions  [THOROUGH]"),
            (self.opt_carve,   "🧬  Binary Data Carving",
             "Scans raw/binary files for patterns  [SLOW]"),
            (self.opt_copy,    "📋  Copy Hits to Output Folder",
             "Copies all matching files to output directory"),
        ]
        for var, label, tip in opts:
            r = tk.Frame(card, bg=T["BG_CARD"])
            r.pack(fill="x", pady=2)
            tk.Checkbutton(
                r, text=label, variable=var,
                bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                activebackground=T["BG_CARD"], activeforeground=T["ACCENT1"],
                selectcolor=T["BG_INPUT"], font=T["FONT_BODY"],
                relief=tk.FLAT, anchor="w"
            ).pack(side="left")
            tk.Label(r, text=tip, bg=T["BG_CARD"],
                     fg=T["TEXT_DIM"], font=("Consolas", 8)).pack(side="left", padx=6)

    def _size_filter_card(self, p):
        self._sec(p, "◈   FILE SIZE FILTER")
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", pady=(0, 4), padx=2)

        row = tk.Frame(card, bg=T["BG_CARD"])
        row.pack(fill="x")

        # Min size
        tk.Label(row, text="Min Size:", bg=T["BG_CARD"],
                 fg=T["TEXT_LABEL"], font=T["FONT_SMALL"]).pack(side="left")
        self.min_size_var = tk.StringVar(value="0")
        tk.Entry(row, textvariable=self.min_size_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=4,
                 width=6).pack(side="left", padx=(4, 0))

        self.min_unit_var = tk.StringVar(value="KB")
        ttk.Combobox(
            row, textvariable=self.min_unit_var,
            values=["B", "KB", "MB"], state="readonly", width=4,
            font=T["FONT_SMALL"]
        ).pack(side="left", padx=(2, 16))

        # Max size
        tk.Label(row, text="Max Size:", bg=T["BG_CARD"],
                 fg=T["TEXT_LABEL"], font=T["FONT_SMALL"]).pack(side="left")
        self.max_size_var = tk.StringVar(value="10")
        tk.Entry(row, textvariable=self.max_size_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=4,
                 width=6).pack(side="left", padx=(4, 0))

        self.max_unit_var = tk.StringVar(value="MB")
        ttk.Combobox(
            row, textvariable=self.max_unit_var,
            values=["B", "KB", "MB", "GB"], state="readonly", width=4,
            font=T["FONT_SMALL"]
        ).pack(side="left", padx=(2, 0))

        tk.Label(card, text="Files outside this range will be skipped.",
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                 font=("Consolas", 8)).pack(anchor="w", pady=(4, 0))

    def _get_size_bytes(self, value_str, unit_str):
        try:
            val = float(value_str)
        except ValueError:
            return None
        multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
        return int(val * multipliers.get(unit_str, 1))

    def _ext_card(self, p):
        self._sec(p, "◈   FILE EXTENSIONS TO SCAN")
        outer = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        outer.pack(fill="x", pady=(0, 4), padx=2)

        ctrl = tk.Frame(outer, bg=T["BG_CARD"])
        ctrl.pack(fill="x", pady=(0, 6))
        make_btn(ctrl, "✔ All",     self._ext_all,     T["ACCENT2"],
                 padx=8, pady=3, font=T["FONT_SMALL"]).pack(side="left", padx=2)
        make_btn(ctrl, "✘ None",    self._ext_none,    T["ACCENT4"],
                 padx=8, pady=3, font=T["FONT_SMALL"]).pack(side="left", padx=2)
        make_btn(ctrl, "↺ Default", self._ext_default, T["ACCENT3"],
                 padx=8, pady=3, font=T["FONT_SMALL"]).pack(side="left", padx=2)

        cf = tk.Frame(outer, bg=T["BG_CARD"])
        cf.pack(fill="x")
        ec = tk.Canvas(cf, bg=T["BG_CARD"], highlightthickness=0, height=130)
        sb = ttk.Scrollbar(cf, orient="vertical", command=ec.yview)
        ec.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        ec.pack(side="left", fill="both", expand=True)

        self._ext_frame = tk.Frame(ec, bg=T["BG_CARD"])
        ec.create_window((0, 0), window=self._ext_frame, anchor="nw")
        self._ext_frame.bind(
            "<Configure>",
            lambda e: ec.configure(scrollregion=ec.bbox("all"))
        )
        self._build_ext_grid()

        legend = tk.Frame(outer, bg=T["BG_CARD"])
        legend.pack(fill="x", pady=(4, 0))
        tk.Label(legend, text="■ Default ON  ", bg=T["BG_CARD"],
                 fg=T["ACCENT1"], font=T["FONT_SMALL"]).pack(side="left")
        tk.Label(legend, text="■ Extra (optional)", bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"], font=T["FONT_SMALL"]).pack(side="left")

    def _build_ext_grid(self):
        for w in self._ext_frame.winfo_children():
            w.destroy()
        all_exts = ([(e, True) for e in DEFAULT_EXTENSIONS] +
                    [(e, False) for e in EXTRA_EXTENSIONS])
        col_l = tk.Frame(self._ext_frame, bg=T["BG_CARD"])
        col_r = tk.Frame(self._ext_frame, bg=T["BG_CARD"])
        col_l.pack(side="left", padx=8, anchor="n")
        col_r.pack(side="left", padx=8, anchor="n")
        for i, (ext, default) in enumerate(all_exts):
            if ext not in self.ext_vars:
                self.ext_vars[ext] = tk.BooleanVar(value=default)
            color = T["ACCENT1"] if default else T["TEXT_DIM"]
            col = col_l if i % 2 == 0 else col_r
            tk.Checkbutton(col, text=ext, variable=self.ext_vars[ext],
                           bg=T["BG_CARD"], fg=color,
                           activebackground=T["BG_CARD"],
                           activeforeground=T["ACCENT1"],
                           selectcolor=T["BG_INPUT"],
                           font=T["FONT_SMALL"], anchor="w",
                           relief=tk.FLAT).pack(anchor="w")

    def _ext_all(self):
        for v in self.ext_vars.values(): v.set(True)

    def _ext_none(self):
        for v in self.ext_vars.values(): v.set(False)

    def _ext_default(self):
        for ext, v in self.ext_vars.items():
            v.set(ext in DEFAULT_EXTENSIONS)

    def _get_selected_exts(self):
        return {e for e, v in self.ext_vars.items() if v.get()}

    def _output_card(self, p):
        self._sec(p, "◈   OUTPUT DIRECTORY")
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", pady=(0, 4), padx=2)
        row = tk.Frame(card, bg=T["BG_CARD"])
        row.pack(fill="x")
        self.output_var = tk.StringVar(value=SCRIPT_DIR)
        tk.Entry(row, textvariable=self.output_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=5
                 ).pack(side="left", fill="x", expand=True)
        make_btn(row, "Browse", self._browse_out, T["ACCENT3"],
                 padx=10, pady=5, font=T["FONT_SMALL"]).pack(side="left", padx=(4, 0))

    def _stats_card(self, p):
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", padx=2, pady=(0, 4))
        grid = tk.Frame(card, bg=T["BG_CARD"])
        grid.pack(fill="x")

        self.stat_files  = tk.StringVar(value="0")
        self.stat_keys   = tk.StringVar(value="0")
        self.stat_status = tk.StringVar(value="IDLE")

        for i, (lbl, var, col) in enumerate([
            ("Files Scanned", self.stat_files,  T["ACCENT1"]),
            ("Keys Found",    self.stat_keys,   T["ACCENT2"]),
            ("Status",        self.stat_status, T["ACCENT3"]),
        ]):
            c = tk.Frame(grid, bg=T["BG_CARD"])
            c.grid(row=0, column=i, padx=12, sticky="nsew")
            grid.grid_columnconfigure(i, weight=1)
            tk.Label(c, text=lbl, bg=T["BG_CARD"],
                     fg=T["TEXT_DIM"], font=T["FONT_SMALL"]).pack()
            tk.Label(c, textvariable=var, bg=T["BG_CARD"],
                     fg=col, font=("Segoe UI", 14, "bold")).pack()

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("DF.Horizontal.TProgressbar",
                        troughcolor=T["BG_INPUT"], background=T["ACCENT1"],
                        bordercolor=T["BORDER"],
                        lightcolor=T["ACCENT1"], darkcolor=T["ACCENT1"])
        self.progress = ttk.Progressbar(card, orient="horizontal",
                                        mode="determinate",
                                        style="DF.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(8, 0))
        self.prog_lbl = tk.Label(card, text="Ready", bg=T["BG_CARD"],
                                 fg=T["TEXT_DIM"], font=T["FONT_SMALL"])
        self.prog_lbl.pack(anchor="w")

    def _console_panel(self, p):
        hdr = tk.Frame(p, bg=T["BG_PANEL"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="◈   CONSOLE OUTPUT",
                 bg=T["BG_PANEL"], fg=T["ACCENT1"],
                 font=T["FONT_HEADER"], pady=6, padx=10).pack(side="left")
        make_btn(hdr, "Clear", self._clear_console, T["TEXT_DIM"],
                 padx=8, pady=3, font=T["FONT_SMALL"]).pack(side="right", padx=8, pady=5)

        frame = tk.Frame(p, bg=T["BG_DARK"])
        frame.pack(fill="both", expand=True, pady=(2, 4))

        self.console = tk.Text(
            frame, bg=T["BG_PANEL"], fg=T["TEXT_PRIMARY"],
            font=T["FONT_CONSOLE"], relief=tk.FLAT, bd=0,
            wrap="word", height=10,
            insertbackground=T["ACCENT1"],
            selectbackground=T["ACCENT1"],
            selectforeground=T["BG_DARK"],
        )
        sb = ttk.Scrollbar(frame, command=self.console.yview)
        self.console.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.console.pack(side="left", fill="both", expand=True)

        self.console.tag_configure("info",    foreground=T["ACCENT1"])
        self.console.tag_configure("success", foreground=T["ACCENT2"])
        self.console.tag_configure("warning", foreground=T["ACCENT3"])
        self.console.tag_configure("error",   foreground=T["ACCENT4"])
        self.console.tag_configure("dim",     foreground=T["TEXT_DIM"])

        self._log(f"Ready  —  {PROJECT_INFO['title']} {PROJECT_INFO['version']}", "info")
        self._log(f"{PROJECT_INFO['uni']}  |  {PROJECT_INFO['subject']}  |  Semester 6", "dim")

    def _table_panel(self, p):
        hdr = tk.Frame(p, bg=T["BG_PANEL"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="◈   FOUND KEYS",
                 bg=T["BG_PANEL"], fg=T["ACCENT2"],
                 font=T["FONT_HEADER"], pady=6, padx=10).pack(side="left")

        style = ttk.Style()
        style.configure("DF.Treeview",
                        background=T["BG_CARD"], foreground=T["TEXT_PRIMARY"],
                        fieldbackground=T["BG_CARD"], bordercolor=T["BORDER"],
                        font=T["FONT_SMALL"], rowheight=24)
        style.configure("DF.Treeview.Heading",
                        background=T["BG_PANEL"], foreground=T["ACCENT1"],
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("DF.Treeview",
                  background=[("selected", T["ACCENT1"])],
                  foreground=[("selected", T["BG_DARK"])])

        frame = tk.Frame(p, bg=T["BG_DARK"])
        frame.pack(fill="both", expand=True, pady=(2, 4))

        cols = ("#", "Validation", "BitLocker Key", "Recovery Key ID",
                "Source", "File Path")
        self.table = ttk.Treeview(frame, columns=cols,
                                  show="headings", style="DF.Treeview")
        widths = {"#": 32, "Validation": 115, "BitLocker Key": 275,
                  "Recovery Key ID": 150, "Source": 95, "File Path": 230}
        for col in cols:
            self.table.heading(col, text=col)
            self.table.column(col, width=widths.get(col, 120), minwidth=30)

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.table.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.table.pack(side="left", fill="both", expand=True)

        tk.Label(p, text="  Double-click a row to view full key details",
                 bg=T["BG_DARK"], fg=T["TEXT_DIM"],
                 font=("Consolas", 8)).pack(anchor="w", padx=8)

        self.table.bind("<Double-1>", self._show_detail)
        
        # Export buttons
        export_frame = tk.Frame(p, bg=T["BG_DARK"])
        export_frame.pack(fill="x", padx=8, pady=10)
        
        tk.Button(export_frame, text="📋 Save as Text (Simple List)",
                 bg=T["ACCENT3"], fg=T["BG_DARK"],
                 font=("Segoe UI", 9), relief=tk.FLAT,
                 padx=15, pady=6, cursor="hand2",
                 command=self._save_text).pack(side="left", padx=5)

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _sec(self, parent, text):
        tk.Label(parent, text=text, bg=T["BG_PANEL"], fg=T["ACCENT1"],
                 font=T["FONT_HEADER"], anchor="w",
                 pady=5, padx=10).pack(fill="x", pady=(4, 0))

    def _browse_src(self):
        p = filedialog.askdirectory(title="Select Drive or Folder to Scan")
        if p: self.source_var.set(p)

    def _browse_out(self):
        p = filedialog.askdirectory(title="Select Output Directory",
                                    initialdir=SCRIPT_DIR)
        if p: self.output_var.set(p)

    def _log(self, msg, level="info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {msg}\n", level)
        self.console.see(tk.END)

    def _clear_console(self):
        self.console.delete("1.0", tk.END)

    def _export_pdf(self):
        """Export results to professional PDF report"""
        if not self.results:
            messagebox.showwarning("No Results", "No keys found to export.")
            return
        
        try:
            # Ask for save location
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
                initialfile=f"BitLocker_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            
            if not filename:
                return
            
            # Simple case info (no dialog needed)
            case_info = {
                'case_number': 'N/A',
                'investigator': 'N/A',
                'device_name': 'N/A',
                'evidence_id': 'N/A',
            }
            
            # Prepare data for PDF
            findings = []
            valid_count = 0
            pattern_count = 0
            
            for result in self.results:
                validity = result.get("Validation", "Unknown")
                if "Valid" in validity:
                    valid_count += 1
                else:
                    pattern_count += 1
                
                findings.append({
                    'key': result.get("BitLocker Key", "N/A"),
                    'validity': validity,
                    'encoding': result.get("Encoding", "N/A"),
                    'location': result.get("Memory Offset", "N/A"),
                })
            
            summary = {
                'scan_type': 'Partition / Disk Scan',
                'scan_location': self.source_var.get() if hasattr(self, 'source_var') else 'N/A',
                'start_time': getattr(self, 'scan_start_time', 'N/A'),
                'end_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_size': 'N/A',
                'keys_found': len(self.results),
                'success_rate': f"{(valid_count / len(self.results) * 100) if self.results else 0:.1f}%"
            }
            
            stats = {
                'total_valid': valid_count,
                'total_pattern_only': pattern_count,
                'false_positive_rate': f"{(pattern_count / len(self.results) * 100) if self.results else 0:.1f}%",
                'scan_speed': 'N/A',
            }
            
            # Generate PDF
            success = generate_partition_report(filename, case_info, findings, summary, stats)
            if success:
                messagebox.showinfo("Success", f"PDF Report saved:\n{filename}")
                self._log(f"PDF exported to: {filename}")
            else:
                messagebox.showerror("Error", "Failed to generate PDF.")
        except Exception as e:
            messagebox.showerror("PDF Export Error", f"{str(e)}")
            self._log(f"PDF export failed: {str(e)}")
    
    def _save_text(self):
        """Save results as plain text file"""
        if not self.results:
            messagebox.showwarning("No Results", "No keys found to save.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"BitLocker_Keys_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not filename:
            return
        
        try:
            # Get case information
            from ui.case_info_dialog import get_case_info
            case = get_case_info()
            
            with open(filename, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("BitLocker Key Finder - Results Export\n")
                f.write("=" * 80 + "\n\n")
                
                # Case Information
                f.write("CASE INFORMATION:\n")
                f.write("-" * 80 + "\n")
                f.write(f"Case Number: {case['case_number']}\n")
                f.write(f"Investigator: {case['investigator']}\n")
                f.write(f"Device Name: {case['device_name']}\n")
                f.write(f"Export Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Notes if present
                if case['notes'] and case['notes'] != 'N/A':
                    f.write("NOTES:\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"{case['notes']}\n\n")
                
                # Scan Details
                f.write("SCAN DETAILS:\n")
                f.write("-" * 80 + "\n")
                f.write(f"Scan Source: {self.source_var.get()}\n")
                f.write(f"Total Keys Found: {len(self.results)}\n\n")
                
                # Results
                f.write("RESULTS:\n")
                f.write("-" * 80 + "\n")
                for i, result in enumerate(self.results, 1):
                    f.write(f"Key #{i}\n")
                    f.write(f"BitLocker Key: {result.get('BitLocker Key', 'N/A')}\n")
                    f.write(f"Validation: {result.get('Validation', 'N/A')}\n")
                    f.write(f"Source: {result.get('Source', 'N/A')}\n")
                    f.write(f"File Path: {result.get('File Path', 'N/A')}\n")
                    f.write(f"Recovery Key ID: {result.get('Recovery Key ID', 'N/A')}\n")
                    f.write("-" * 80 + "\n")
            
            messagebox.showinfo("Success", f"Results saved to:\n{filename}")
            self._log(f"Text file exported: {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed:\n{str(e)}")

    def _go_back(self):
        if self.scanning:
            if not messagebox.askyesno("Scan Running",
                                       "Scan is running. Stop and go back?"):
                return
            self.stop_flag.set()
        self.on_back()

    # ── Scan Logic ─────────────────────────────────────────────────────────────
    def _start_scan(self):
        folder = self.source_var.get().strip()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Invalid Path",
                                 "Please select a valid drive or folder.")
            return

        selected = self._get_selected_exts()
        if not selected and not self.opt_name.get():
            messagebox.showwarning("Nothing Selected",
                                   "Select at least one extension or enable File Name Search.")
            return

        # Parse size limits
        min_bytes = self._get_size_bytes(self.min_size_var.get(), self.min_unit_var.get())
        max_bytes = self._get_size_bytes(self.max_size_var.get(), self.max_unit_var.get())
        if min_bytes is None or max_bytes is None:
            messagebox.showerror("Invalid Size", "Please enter valid numeric size values.")
            return

        # Patch the scanner with size limits
        import modules.partition_scan as ps
        ps._ACTIVE_MIN_BYTES = min_bytes
        ps._ACTIVE_MAX_BYTES = max_bytes
        ps._ACTIVE_EXTS = selected

        self.results.clear()
        self.stop_flag.clear()
        self._clear_table()
        self._clear_console()
        self.stat_files.set("0")
        self.stat_keys.set("0")
        self.stat_status.set("SCANNING")
        self.progress["value"] = 0
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        self._log(f"Scanning: {folder}", "info")
        self._log(f"Size filter: {self.min_size_var.get()} {self.min_unit_var.get()} "
                  f"→ {self.max_size_var.get()} {self.max_unit_var.get()}", "dim")
        self._log(f"Extensions: {', '.join(sorted(selected))}", "dim")

        t = threading.Thread(target=self._run_scan, args=(folder,), daemon=True)
        t.start()

    def _run_scan(self, folder):
        try:
            def prog(cur, tot):
                pct = int((cur / tot) * 100) if tot else 0
                self.master.after(0, lambda: self._upd_prog(cur, tot, pct))

            scan_partition(
                folder=folder, results=self.results,
                log_fn=lambda m, l="info": self.master.after(
                    0, lambda msg=m, lvl=l: self._log(msg, lvl)),
                progress_fn=prog,
                do_name_search=self.opt_name.get(),
                do_content_search=self.opt_content.get(),
                do_binary_carve=self.opt_carve.get(),
                stop_flag=self.stop_flag,
            )
        except Exception as e:
            self.master.after(0, lambda: self._log(f"[ERROR] {e}", "error"))
        finally:
            self.master.after(0, self._scan_done)

    def _upd_prog(self, cur, tot, pct):
        self.progress["maximum"] = tot
        self.progress["value"]   = cur
        self.stat_files.set(str(cur))
        self.stat_keys.set(str(len(self.results)))
        self.prog_lbl.config(text=f"Scanning...  {cur}/{tot}  ({pct}%)")
        self._refresh_table()

    def _stop_scan(self):
        self.stop_flag.set()
        self._log("Stopping scan...", "warning")
        self.stat_status.set("STOPPED")

    def _scan_done(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress["value"] = self.progress["maximum"]
        self.prog_lbl.config(text="Scan complete.")
        self.stat_status.set("DONE")
        self.stat_keys.set(str(len(self.results)))
        self._refresh_table()
        self._log(
            f"═══ SCAN COMPLETE ═══   {len(self.results)} key(s) found.", "success")
        if self.opt_copy.get() and self.results:
            self._copy_files()

    # ── Table ──────────────────────────────────────────────────────────────────
    def _refresh_table(self):
        self._clear_table()
        for i, row in enumerate(self.results, 1):
            validation = row.get("Validation", "N/A")
            # Choose row tag by validation status
            if validation.startswith("Valid"):
                tag = "valid"
            elif validation.startswith("Pattern"):
                tag = "pattern"
            elif validation.startswith("N/A"):
                tag = "na_even" if i % 2 == 0 else "na_odd"
            else:
                tag = "even" if i % 2 == 0 else "odd"
            self.table.insert("", "end",
                              values=(i,
                                      validation,
                                      row.get("BitLocker Key", ""),
                                      row.get("Recovery Key ID", ""),
                                      row.get("Source", ""),
                                      row.get("File Path", "")),
                              tags=(tag,))
        # Colour semantics:
        #   valid   → green tint (mod-11 structurally valid)
        #   pattern → amber tint (regex match but failed mod-11)
        #   N/A     → neutral zebra (BEK binary, name-only hit)
        self.table.tag_configure("valid",    background="#1a3a2a",
                                 foreground=T["ACCENT2"])
        self.table.tag_configure("pattern",  background="#3a2d1a",
                                 foreground=T["ACCENT3"])
        self.table.tag_configure("na_even",  background=T["BG_INPUT"])
        self.table.tag_configure("na_odd",   background=T["BG_CARD"])
        self.table.tag_configure("even",     background=T["BG_INPUT"])
        self.table.tag_configure("odd",      background=T["BG_CARD"])

    def _clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def _show_detail(self, event):
        sel = self.table.selection()
        if not sel: return
        vals = self.table.item(sel[0])["values"]
        if not vals or len(vals) < 6: return
        row_data = {
            "Validation":      vals[1],
            "BitLocker Key":   vals[2],
            "Recovery Key ID": vals[3],
            "Source":          vals[4],
            "File Path":       vals[5],
        }
        KeyDetailPopup(self.master, row_data)

    def _copy_files(self):
        out = self.output_var.get()
        copied = 0
        for row in self.results:
            src = row.get("File Path", "")
            if src and os.path.isfile(src):
                try:
                    shutil.copy2(src, out)
                    copied += 1
                except Exception as e:
                    self._log(f"[COPY ERROR] {src}: {e}", "error")
        self._log(f"Copied {copied} file(s) to {out}", "success")

    def _export_pdf(self):
        if not self.results:
            messagebox.showinfo("No Data", "No keys found yet. Run a scan first.")
            return
        
        # Get project root
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Create filename with timestamp
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"BitLocker_Results_{ts}.txt"
        filepath = os.path.join(project_root, filename)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("BitLocker Key Finder v1.1 — Partition Scan Results\n")
                f.write("=" * 80 + "\n\n")
                
                # Header info
                f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Location: {self.source_var.get().strip() or 'Default'}\n")
                f.write(f"Total Files Scanned: {len([r for r in self.results if r.get('Source') == 'File Name Match'])}\n")
                f.write(f"Total Keys Found: {len(self.results)}\n")
                valid_count = sum(1 for r in self.results if r.get("Validation") == "Valid (mod-11)")
                f.write(f"Valid Keys (mod-11): {valid_count}\n")
                f.write("-" * 80 + "\n\n")
                
                # Results
                if self.results:
                    f.write("FOUND KEYS:\n")
                    f.write("-" * 80 + "\n\n")
                    
                    for i, row in enumerate(self.results, 1):
                        f.write(f"[{i}] BitLocker Recovery Key\n")
                        f.write(f"    Validation:      {row.get('Validation', 'N/A')}\n")
                        f.write(f"    Key:             {row.get('BitLocker Key', 'N/A')}\n")
                        f.write(f"    Recovery ID:     {row.get('Recovery Key ID', 'N/A')}\n")
                        f.write(f"    Source:          {row.get('Source', 'N/A')}\n")
                        f.write(f"    File Path:       {row.get('File Path', 'N/A')}\n")
                        f.write(f"    File Size:       {row.get('File Size', 'N/A')}\n")
                        f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("End of Report\n")
                f.write("=" * 80 + "\n")
            
            messagebox.showinfo("Export Complete", f"Results saved:\n{filename}\n\n{project_root}")
            self._log(f"Exported to: {filename}", "success")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")

    def _clear_all(self):
        self.results.clear()
        self._clear_table()
        self._clear_console()
        self.stat_files.set("0")
        self.stat_keys.set("0")
        self.stat_status.set("IDLE")
        self.progress["value"] = 0
        self.prog_lbl.config(text="Ready")
        self._log("Cleared. Ready for new scan.", "dim")


# ══════════════════════════════════════════════════════════════════════════════
#  APP CONTROLLER
# ══════════════════════════════════════════════════════════════════════════════
class App:
    def __init__(self, master):
        self.master = master
        # Start with splash, then case dialog, then menu
        SplashScreen(master, self._show_case_dialog)

    def _show_case_dialog(self):
        """Show case information dialog after splash"""
        from ui.case_info_dialog import show_case_dialog
        for w in self.master.winfo_children():
            w.destroy()
        show_case_dialog(self.master, self._show_menu, self._exit_app)

    def _show_menu(self):
        for w in self.master.winfo_children():
            w.destroy()
        menu = MainMenu(self.master, self._menu_choice)
        # Rebind menu keys
        self.master.bind("1", lambda e: self._menu_choice(1))
        self.master.bind("2", lambda e: self._menu_choice(2))
        self.master.bind("3", lambda e: self._menu_choice(3))
        self.master.bind("4", lambda e: self._menu_choice(4))  # NEW
        self.master.bind("5", lambda e: self._menu_choice(5))  # NEW
        self.master.bind("6", lambda e: self._menu_choice(6))  # NEW

    def _exit_app(self):
        """Exit application from case dialog"""
        self.master.destroy()

    def _menu_choice(self, choice):
        # Unbind menu keys to prevent accidental triggering while in a screen
        self.master.unbind("1")
        self.master.unbind("2")
        self.master.unbind("3")
        self.master.unbind("4")
        self.master.unbind("5")
        self.master.unbind("6")
        
        if choice == 1:
            for w in self.master.winfo_children():
                w.destroy()
            RamScreen(self.master, self._show_menu)
        elif choice == 2:
            for w in self.master.winfo_children():
                w.destroy()
            ScanScreen(self.master, self._show_menu)
        elif choice == 3:  # NEW - Settings (was 4)
            for w in self.master.winfo_children():
                w.destroy()
            settings = SettingsScreen(self.master, self._show_menu)
            settings.build().pack(fill="both", expand=True)
        elif choice == 4:  # NEW - Help (was 5)
            for w in self.master.winfo_children():
                w.destroy()
            help_screen = HelpScreen(self.master, self._show_menu)
            help_screen.build().pack(fill="both", expand=True)
        elif choice == 5:  # NEW - About (was 6)
            for w in self.master.winfo_children():
                w.destroy()
            about = AboutScreen(self.master, self._show_menu)
            about.build().pack(fill="both", expand=True)
        elif choice == 6:  # Exit (was 3)
            if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
                self.master.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def launch_app():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    launch_app()