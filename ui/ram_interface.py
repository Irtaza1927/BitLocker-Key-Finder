"""
ram_interface.py
─────────────────────────────────────────────────────────────────────────────
BitLocker Key Finder — Part A: RAM Extraction GUI
FAST-NUCES Islamabad | Digital Forensics | Semester 6

Uses the SAME theme, fonts, card layout, and button style as Part B (interface.py).
"""

import os
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from modules.live_ram import (
    scan_dump_file,
    run_live_pipeline,
    run_volatility3,
    save_ram_report,
    check_winpmem,
    check_admin,
    check_volatility3,
    RAM_SIZE_OPTIONS,
    SCAN_DEPTH_OPTIONS,
)
from modules.pdf_reporter import generate_ram_report  # NEW - PDF export
from ui.case_dialog import CaseInfoDialog  # NEW - Case info dialog

import theme_config  # Import global theme config

# ═════════════════════════════════════════════════════════════════════════════
#  PROJECT INFO
# ═════════════════════════════════════════════════════════════════════════════
PROJECT_INFO = {
    "title":   "BitLocker Key Finder",
    "version": "v1.1",
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

# ═════════════════════════════════════════════════════════════════════════════
#  THEME  — from global theme_config (changes with user selection)
# ═════════════════════════════════════════════════════════════════════════════
T = theme_config.get_current_theme()


# ═════════════════════════════════════════════════════════════════════════════
#  HELPER — identical to Part B make_btn
# ═════════════════════════════════════════════════════════════════════════════
def make_btn(parent, text, cmd, fg_color, **kw):
    padx = kw.pop("padx", 14)
    pady = kw.pop("pady", 7)
    font = kw.pop("font", T["FONT_BODY"])
    btn = tk.Button(
        parent, text=text, command=cmd,
        bg=T["BG_CARD"], fg=fg_color,
        activebackground=fg_color, activeforeground=T["BG_DARK"],
        font=font, relief=tk.FLAT, bd=0, cursor="hand2",
        padx=padx, pady=pady,
        highlightthickness=1, highlightbackground=fg_color,
        **kw
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=fg_color, fg=T["BG_DARK"]))
    btn.bind("<Leave>", lambda e: btn.config(bg=T["BG_CARD"], fg=fg_color))
    return btn


def _sec(parent, text):
    tk.Label(
        parent, text=text,
        bg=T["BG_PANEL"], fg=T["ACCENT1"],
        font=T["FONT_HEADER"], anchor="w",
        pady=5, padx=10
    ).pack(fill="x", pady=(4, 0))


# ═════════════════════════════════════════════════════════════════════════════
#  RAM SCREEN
# ═════════════════════════════════════════════════════════════════════════════
class RamScreen:
    def __init__(self, master, on_back):
        self.master    = master
        self.on_back   = on_back
        self.results   = []
        self.stop_flag = threading.Event()
        self.scanning  = False
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────
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

        self._topbar()
        self._body()
        self._footer()
        self.master.bind("<Escape>", lambda e: self._go_back())
        self._tick_clock()
        self._refresh_indicators()

    # ── Top bar — identical layout to Part B ───────────────────────────────
    def _topbar(self):
        bar = tk.Frame(self.master, bg=T["BG_PANEL"])
        bar.pack(fill="x")

        tk.Label(
            bar,
            text=f"  ⚡  LIVE RAM EXTRACTION  —  "
                 f"{PROJECT_INFO['title']} {PROJECT_INFO['version']}",
            font=T["FONT_HEADER"],
            bg=T["BG_PANEL"], fg=T["ACCENT1"], pady=8
        ).pack(side="left", padx=8)

        btn_f = tk.Frame(bar, bg=T["BG_PANEL"])
        btn_f.pack(side="right", padx=8, pady=5)

        make_btn(btn_f, "◄ MENU", self._go_back, T["ACCENT3"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        tk.Frame(btn_f, bg=T["BORDER"], width=1).pack(
            side="left", fill="y", padx=6, pady=4)

        self.start_btn = tk.Button(
            btn_f, text="▶  START",
            command=self._start,
            bg=T["ACCENT2"], fg=T["BG_DARK"],
            activebackground="#4caf50", activeforeground=T["BG_DARK"],
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT, bd=0, cursor="hand2", padx=14, pady=6,
        )
        self.start_btn.pack(side="left", padx=3)

        self.stop_btn = tk.Button(
            btn_f, text="■  STOP",
            command=self._stop,
            bg=T["ACCENT4"], fg="white",
            activebackground="#c0392b", activeforeground="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT, bd=0, cursor="hand2",
            padx=10, pady=6, state=tk.DISABLED,
        )
        self.stop_btn.pack(side="left", padx=3)

        make_btn(btn_f, "📄 EXPORT", self._export, T["ACCENT3"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        make_btn(btn_f, "🗑 CLEAR", self._clear_all, T["TEXT_DIM"],
                 padx=10, pady=6, font=T["FONT_SMALL"]).pack(side="left", padx=3)

        tk.Frame(self.master, bg=T["ACCENT1"], height=2).pack(fill="x")

    # ── Body ───────────────────────────────────────────────────────────────
    def _body(self):
        body = tk.Frame(self.master, bg=T["BG_DARK"])
        body.pack(fill="both", expand=True, padx=8, pady=6)

        # LEFT panel — scrollable, same as Part B
        left_outer = tk.Frame(body, bg=T["BG_DARK"], width=490)
        left_outer.pack(side="left", fill="y", padx=(0, 6))
        left_outer.pack_propagate(False)

        lc = tk.Canvas(left_outer, bg=T["BG_DARK"],
                       highlightthickness=0, width=475)
        ls = ttk.Scrollbar(left_outer, orient="vertical", command=lc.yview)
        lc.configure(yscrollcommand=ls.set)
        ls.pack(side="right", fill="y")
        lc.pack(side="left", fill="both", expand=True)

        left = tk.Frame(lc, bg=T["BG_DARK"])
        lw = lc.create_window((0, 0), window=left, anchor="nw")
        left.bind("<Configure>",
                  lambda e: lc.configure(scrollregion=lc.bbox("all")))
        lc.bind("<Configure>",
                lambda e: lc.itemconfig(lw, width=e.width))
        lc.bind("<MouseWheel>",
                lambda e: lc.yview_scroll(int(-1*(e.delta/120)), "units"))
        left.bind("<MouseWheel>",
                  lambda e: lc.yview_scroll(int(-1*(e.delta/120)), "units"))

        self._mode_card(left)
        self._acquire_card(left)
        self._scan_card(left)
        # self._output_card(left)  # Not needed - Browse button now in _acquire_card
        self._stats_card(left)
        
        # Initialize visibility based on default mode
        self._on_mode_change()

        # RIGHT panel
        right = tk.Frame(body, bg=T["BG_DARK"])
        right.pack(side="left", fill="both", expand=True)
        self._console_panel(right)
        self._table_panel(right)

    # ── Mode selector ──────────────────────────────────────────────────────
    def _mode_card(self, p):
        _sec(p, "◈   SELECT MODE")
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=10)
        card.pack(fill="x", pady=(0, 4), padx=2)

        self.mode_var = tk.IntVar(value=1)
        modes = [
            (1, "⚡  Live RAM Dump + Scan",
             "Acquire physical memory via winpmem, then scan automatically"),
            (2, "📂  Load Dump File + Scan",
             "Browse to an existing .raw / .dmp / .vmem / .mem file"),
        ]
        for val, label, tip in modes:
            rf = tk.Frame(card, bg=T["BG_CARD"])
            rf.pack(fill="x", pady=3)
            tk.Radiobutton(
                rf, text=label, variable=self.mode_var, value=val,
                command=self._on_mode_change,
                bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                activebackground=T["BG_CARD"], activeforeground=T["ACCENT1"],
                selectcolor=T["BG_INPUT"],
                font=T["FONT_BODY"], relief=tk.FLAT, anchor="w",
            ).pack(anchor="w")
            tk.Label(rf, text=f"    {tip}",
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                     font=("Consolas", 8), anchor="w").pack(anchor="w")

    # ── Acquisition options ────────────────────────────────────────────────
    def _acquire_card(self, p):
        _sec(p, "◈   LIVE RAM ACQUISITION")
        self.acq_card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=10)
        self.acq_card.pack(fill="x", pady=(0, 4), padx=2)

        # Info
        tk.Label(
            self.acq_card,
            text="Acquires FULL physical RAM via winpmem. Click START to begin.",
            bg=T["BG_CARD"], fg=T["ACCENT2"],
            font=T["FONT_SMALL"], justify="left", wraplength=280
        ).pack(anchor="w", pady=(0, 8))

        # Status indicators
        stat = tk.Frame(self.acq_card, bg=T["BG_CARD"])
        stat.pack(fill="x", pady=(0, 8))
        self.winpmem_lbl = tk.Label(stat, text="",
                                    bg=T["BG_CARD"], font=T["FONT_SMALL"])
        self.winpmem_lbl.pack(anchor="w")
        self.admin_lbl = tk.Label(stat, text="",
                                   bg=T["BG_CARD"], font=T["FONT_SMALL"])
        self.admin_lbl.pack(anchor="w")

        tk.Frame(self.acq_card, bg=T["BORDER"], height=1).pack(fill="x", pady=6)

        # Hidden variables for compatibility
        self.ram_size_var = tk.StringVar(value="Full RAM")
        self.custom_size_var = tk.StringVar(value="0")
        self.keep_dump_var = tk.BooleanVar(value=True)
        
        # Default path - user can change via Browse button
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_path = f"ram_dump_{timestamp}.raw"
        
        self.dump_path_var = tk.StringVar(value=default_path)
        
        # Browse button for dump location
        path_row = tk.Frame(self.acq_card, bg=T["BG_CARD"])
        path_row.pack(fill="x", pady=(0, 0))
        tk.Label(path_row, text="Save to:",
                 bg=T["BG_CARD"], fg=T["TEXT_LABEL"],
                 font=T["FONT_SMALL"]).pack(side="left")
        tk.Entry(path_row, textvariable=self.dump_path_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=5
                 ).pack(side="left", fill="x", expand=True, padx=(6, 4))
        make_btn(path_row, "Browse", self._browse_dump_path, T["ACCENT1"],
                 padx=10, pady=5, font=T["FONT_SMALL"]).pack(side="left", padx=(0, 0))

    def _scan_card(self, p):
        _sec(p, "◈   SCAN OPTIONS")
        self.scan_card = tk.Frame(p, bg=T["BG_CARD"])
        self.scan_card.pack(fill="x", pady=(0, 4), padx=2)
        
        card = tk.Frame(self.scan_card, bg=T["BG_CARD"], padx=10, pady=10)
        card.pack(fill="x")

        # Load dump file row (mode 2 only)
        self.load_row = tk.Frame(card, bg=T["BG_CARD"])
        self.load_row.pack(fill="x", pady=(0, 8))
        tk.Label(self.load_row, text="Dump file:",
                 bg=T["BG_CARD"], fg=T["TEXT_LABEL"],
                 font=T["FONT_SMALL"]).pack(side="left")
        self.load_path_var = tk.StringVar()
        tk.Entry(self.load_row, textvariable=self.load_path_var,
                 bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                 insertbackground=T["ACCENT1"],
                 font=T["FONT_BODY"], relief=tk.FLAT, bd=5
                 ).pack(side="left", fill="x", expand=True, padx=(6, 4))
        make_btn(self.load_row, "Browse", self._browse_load, T["ACCENT1"],
                 padx=10, pady=5,
                 font=T["FONT_SMALL"]).pack(side="left")
        self.load_row.pack_forget()   # hidden until mode 2 selected

        tk.Frame(card, bg=T["BORDER"], height=1).pack(fill="x", pady=4)

        # Scan depth
        tk.Label(card, text="Scan Depth:",
                 bg=T["BG_CARD"], fg=T["TEXT_LABEL"],
                 font=T["FONT_SMALL"]).pack(anchor="w")

        self.depth_var = tk.StringVar(value="Full Dump")
        depth_keys = [k for k in SCAN_DEPTH_OPTIONS if k != "Custom"]
        df = tk.Frame(card, bg=T["BG_CARD"])
        df.pack(fill="x", pady=4)
        for i, key in enumerate(depth_keys):
            tk.Radiobutton(
                df, text=key, variable=self.depth_var, value=key,
                command=self._on_depth_change,
                bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                activebackground=T["BG_CARD"], activeforeground=T["ACCENT1"],
                selectcolor=T["BG_INPUT"],
                font=T["FONT_SMALL"], relief=tk.FLAT,
            ).grid(row=0, column=i, sticky="w", padx=10, pady=2)

        cdf = tk.Frame(card, bg=T["BG_CARD"])
        cdf.pack(fill="x", pady=(2, 0))
        tk.Radiobutton(
            cdf, text="Custom (MB):",
            variable=self.depth_var, value="Custom",
            command=self._on_depth_change,
            bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
            activebackground=T["BG_CARD"], activeforeground=T["ACCENT1"],
            selectcolor=T["BG_INPUT"],
            font=T["FONT_SMALL"], relief=tk.FLAT,
        ).pack(side="left")
        self.custom_depth_var = tk.StringVar(value="100")
        self.custom_depth_entry = tk.Entry(
            cdf, textvariable=self.custom_depth_var,
            bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
            insertbackground=T["ACCENT1"],
            font=T["FONT_BODY"], relief=tk.FLAT, bd=4,
            width=8, state=tk.DISABLED,
        )
        self.custom_depth_entry.pack(side="left", padx=6)
        tk.Label(cdf, text="MB", bg=T["BG_CARD"],
                 fg=T["TEXT_LABEL"], font=T["FONT_SMALL"]).pack(side="left")

        tk.Frame(card, bg=T["BORDER"], height=1).pack(fill="x", pady=8)

        # Encoding passes
        enc_f = tk.Frame(card, bg=T["BG_CARD"])
        enc_f.pack(fill="x")
        tk.Label(enc_f, text="Encoding passes:",
                 bg=T["BG_CARD"], fg=T["TEXT_LABEL"],
                 font=T["FONT_SMALL"]).pack(side="left")
        self.enc_var = tk.StringVar(value="fast")
        opts = [
            ("fast", "⚡  Fast  (UTF-8 + UTF-16-LE)  [recommended]"),
            ("all",  "🔍  All encodings  (thorough, slower)"),
        ]
        for val, label in opts:
            tk.Radiobutton(
                enc_f, text=label, variable=self.enc_var, value=val,
                bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                activebackground=T["BG_CARD"], activeforeground=T["ACCENT1"],
                selectcolor=T["BG_INPUT"],
                font=T["FONT_SMALL"], relief=tk.FLAT,
            ).pack(side="left", padx=10)

        # Volatility3 disabled — not required for semester project
        # Recovery password carving via regex is sufficient for submission

    # ── Output directory ───────────────────────────────────────────────────
    def _output_card(self, p):
        _sec(p, "◈   OUTPUT DIRECTORY")
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
        make_btn(row, "Browse", self._browse_output, T["ACCENT3"],
                 padx=10, pady=5, font=T["FONT_SMALL"]).pack(side="left", padx=(4, 0))

    # ── Stats card — identical to Part B ──────────────────────────────────
    def _stats_card(self, p):
        card = tk.Frame(p, bg=T["BG_CARD"], padx=10, pady=8)
        card.pack(fill="x", padx=2, pady=(0, 4))
        grid = tk.Frame(card, bg=T["BG_CARD"])
        grid.pack(fill="x")

        self.stat_keys   = tk.StringVar(value="0")
        self.stat_valid  = tk.StringVar(value="0")
        self.stat_status = tk.StringVar(value="IDLE")

        for i, (lbl, var, col) in enumerate([
            ("Keys Found",    self.stat_keys,   T["ACCENT1"]),
            ("Valid (mod-11)", self.stat_valid,  T["ACCENT2"]),
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
        style.configure("RAM.Horizontal.TProgressbar",
                        troughcolor=T["BG_INPUT"], background=T["ACCENT2"],
                        bordercolor=T["BORDER"],
                        lightcolor=T["ACCENT2"], darkcolor=T["ACCENT2"],
                        thickness=20)  # Thicker bar
        self.progress = ttk.Progressbar(
            card, orient="horizontal", mode="determinate",
            style="RAM.Horizontal.TProgressbar", length=400)
        self.progress.pack(fill="x", pady=(12, 4), ipady=4)
        self.prog_lbl = tk.Label(card, text="Ready",
                                  bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                                  font=T["FONT_BODY"])
        self.prog_lbl.pack(anchor="w", pady=(0, 4))

    # ── Console — identical to Part B ─────────────────────────────────────
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

    # ── Keys table ─────────────────────────────────────────────────────────
    def _table_panel(self, p):
        hdr = tk.Frame(p, bg=T["BG_PANEL"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="◈   FOUND KEYS",
                 bg=T["BG_PANEL"], fg=T["ACCENT2"],
                 font=T["FONT_HEADER"], pady=6, padx=10).pack(side="left")

        style = ttk.Style()
        style.configure("RAM.Treeview",
                        background=T["BG_CARD"], foreground=T["TEXT_PRIMARY"],
                        fieldbackground=T["BG_CARD"], bordercolor=T["BORDER"],
                        font=T["FONT_SMALL"], rowheight=24)
        style.configure("RAM.Treeview.Heading",
                        background=T["BG_PANEL"], foreground=T["ACCENT1"],
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("RAM.Treeview",
                  background=[("selected", T["ACCENT1"])],
                  foreground=[("selected", T["BG_DARK"])])

        frame = tk.Frame(p, bg=T["BG_DARK"])
        frame.pack(fill="both", expand=True, pady=(2, 4))

        cols = ("#", "Key Type", "Validation", "BitLocker Key",
                "Memory Offset", "Encoding", "Recovery Key ID")
        self.table = ttk.Treeview(
            frame, columns=cols, show="headings", style="RAM.Treeview")
        widths = {
            "#": 32, "Key Type": 120, "Validation": 110,
            "BitLocker Key": 260, "Memory Offset": 130,
            "Encoding": 75, "Recovery Key ID": 140,
        }
        for col in cols:
            self.table.heading(col, text=col)
            self.table.column(col, width=widths.get(col, 100), minwidth=30)

        # Scrollbars using grid layout (more reliable)
        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.table.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout for proper scrollbar alignment
        self.table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tk.Label(p, text="  Double-click a row to copy key to clipboard  |  Scroll left-right to see all columns",
                 bg=T["BG_DARK"], fg=T["TEXT_DIM"],
                 font=("Consolas", 8)).pack(anchor="w", padx=8)
        self.table.bind("<Double-1>", lambda e: self._on_result_click(e))
        
        # Export buttons
        export_frame = tk.Frame(p, bg=T["BG_DARK"])
        export_frame.pack(fill="x", padx=8, pady=10)
        
        tk.Button(export_frame, text="📋 Save as Text (Simple List)",
                 bg=T["ACCENT3"], fg=T["BG_DARK"],
                 font=("Segoe UI", 9), relief=tk.FLAT,
                 padx=15, pady=6, cursor="hand2",
                 command=self._save_text).pack(side="left", padx=5)

    # ── Footer — identical to Part B ───────────────────────────────────────
    def _footer(self):
        f = tk.Frame(self.master, bg=T["BG_PANEL"], height=26)
        f.pack(fill="x", side="bottom")
        f.pack_propagate(False)
        members = "  |  ".join(f"{n} [{r}]" for n, r in PROJECT_INFO["members"])
        tk.Label(f, text=f"  {PROJECT_INFO['uni']}  ◈  {members}",
                 bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
                 font=T["FONT_SMALL"]).pack(side="left", padx=8)
        self.clock_lbl = tk.Label(f, text="",
                                   bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
                                   font=T["FONT_SMALL"])
        self.clock_lbl.pack(side="right", padx=10)

    def _tick_clock(self):
        self.clock_lbl.config(
            text=datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.master.after(1000, self._tick_clock)

    # ── Status indicators ──────────────────────────────────────────────────
    def _refresh_indicators(self):
        if check_winpmem():
            self.winpmem_lbl.config(
                text="  ✓  winpmem.exe found", fg=T["ACCENT2"])
        else:
            self.winpmem_lbl.config(
                text="  ✗  winpmem.exe NOT found — place in assets/winpmem.exe",
                fg=T["ACCENT4"])
        if check_admin():
            self.admin_lbl.config(
                text="  ✓  Running as Administrator", fg=T["ACCENT2"])
        else:
            self.admin_lbl.config(
                text="  ✗  Not Administrator — live acquisition will fail",
                fg=T["ACCENT3"])

    # ── Option callbacks ───────────────────────────────────────────────────
    def _on_mode_change(self):
        """Show/hide cards based on selected mode."""
        if self.mode_var.get() == 1:
            # Mode 1: Live acquisition — hide load_row, hide scan_card
            self.acq_card.pack(fill="x", pady=(0, 4), padx=2)
            self.load_row.pack_forget()
            self.scan_card.pack_forget()  # No scan options needed
        else:
            # Mode 2: Load dump — show load_row and scan_card
            self.acq_card.pack_forget()
            self.load_row.pack(fill="x", pady=(0, 8))
            self.scan_card.pack(fill="x", pady=(0, 4), padx=2)  # Show scan options

    def _on_depth_change(self):
        s = tk.NORMAL if self.depth_var.get() == "Custom" else tk.DISABLED
        self.custom_depth_entry.config(state=s)

    # ── Browse ─────────────────────────────────────────────────────────────
    def _browse_dump_path(self):
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ram_dump_{ts}.raw"
        
        p = filedialog.asksaveasfilename(
            title="Save RAM Dump As",
            initialdir="F:\\",
            initialfile=filename,
            defaultextension=".raw",
            filetypes=[("Raw memory", "*.raw"), ("All files", "*.*")],
        )
        if p and p.strip():
            abs_path = os.path.abspath(p)
            self.dump_path_var.set(abs_path)

    def _browse_load(self):
        p = filedialog.askopenfilename(
            title="Select RAM Dump File",
            filetypes=[
                ("Memory dumps", "*.raw *.dmp *.vmem *.mem *.bin *.img"),
                ("All files", "*.*"),
            ],
        )
        if p:
            self.load_path_var.set(p)

    def _browse_output(self):
        p = filedialog.askdirectory(title="Select Output Directory")
        if p:
            self.output_var.set(p)

    # ── Scan logic ─────────────────────────────────────────────────────────
    def _get_scan_max_bytes(self):
        key = self.depth_var.get()
        if key == "Custom":
            try:
                return int(self.custom_depth_var.get()) * 1024 * 1024
            except ValueError:
                messagebox.showerror("Invalid Input",
                                     "Custom depth must be a whole number.")
                return -1
        return SCAN_DEPTH_OPTIONS.get(key)

    def _get_acquire_mb(self):
        key = self.ram_size_var.get()
        if key == "Custom":
            try:
                return int(self.custom_size_var.get())
            except ValueError:
                messagebox.showerror("Invalid Input",
                                     "Custom size must be a whole number.")
                return -1
        return RAM_SIZE_OPTIONS.get(key)

    def _start(self):
        scan_max = self._get_scan_max_bytes()
        if scan_max == -1:
            return

        self.results.clear()
        self.stop_flag.clear()
        self._clear_table()
        self._clear_console()
        self.stat_keys.set("0")
        self.stat_valid.set("0")
        self.stat_status.set("SCANNING")
        self.progress["value"] = 0
        self.prog_lbl.config(text="Starting...")
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        enc  = self.enc_var.get()

        if self.mode_var.get() == 1:
            acq_mb = self._get_acquire_mb()
            if acq_mb == -1:
                self._scan_done()
                return
            dump = self.dump_path_var.get().strip()
            
            # CRITICAL: Log the exact path being used
            self._log(f"[DEBUG] Raw dump_path_var: {dump}", "info")
            dump = os.path.abspath(dump)
            self._log(f"[DEBUG] Absolute dump path: {dump}", "info")
            
            if not dump:
                messagebox.showerror("Error", "Set a dump output path first.")
                self._scan_done()
                return
            self._log("[MODE] Live RAM Acquisition + Scan", "info")
            t = threading.Thread(
                target=self._run_live,
                args=(dump, acq_mb, scan_max, enc,
                      self.keep_dump_var.get()),
                daemon=True,
            )
        else:
            dump = self.load_path_var.get().strip()
            if not dump or not os.path.isfile(dump):
                messagebox.showerror("Error", "Select a valid dump file.")
                self._scan_done()
                return
            self._log(f"[MODE] Load Dump: {os.path.basename(dump)}", "info")
            t = threading.Thread(
                target=self._run_load,
                args=(dump, scan_max, enc),
                daemon=True,
            )
        t.start()

    def _run_live(self, dump, acq_mb, scan_max, enc, keep):
        try:
            run_live_pipeline(
                output_path=dump, size_mb=acq_mb,
                results=self.results,
                log_fn=self._safe_log,
                stop_flag=self.stop_flag,
                progress_fn=self._safe_progress,
                scan_max_bytes=scan_max,
                encoding_mode=enc,
                keep_dump=keep,
            )
        except Exception as e:
            self.master.after(0, lambda: self._log(f"[ERROR] {e}", "error"))
        finally:
            self.master.after(0, self._scan_done)

    def _run_load(self, dump, scan_max, enc):
        try:
            scan_dump_file(
                dump_path=dump, results=self.results,
                log_fn=self._safe_log,
                stop_flag=self.stop_flag,
                progress_fn=self._safe_progress,
                max_bytes=scan_max,
                encoding_mode=enc,
            )
        except Exception as e:
            self.master.after(0, lambda: self._log(f"[ERROR] {e}", "error"))
        finally:
            self.master.after(0, self._scan_done)

    def _safe_log(self, msg, level="info"):
        self.master.after(0, lambda m=msg, l=level: self._log(m, l))

    def _safe_progress(self, done, total):
        def _upd():
            pct = int((done / total) * 100) if total else 0
            pct = min(pct, 100)  # Cap at 100% maximum
            self.progress["maximum"] = total
            self.progress["value"]   = done
            mb_done  = done  / (1024**2)
            mb_total = total / (1024**2)
            
            # Different label for Part A vs Part B
            action = "Acquiring" if self.mode_var.get() == 1 else "Scanning"
            
            self.prog_lbl.config(
                text=f"{action}...  {mb_done:.1f} MB / {mb_total:.1f} MB  ({pct}%)",
                fg=T["ACCENT2"])
            self._refresh_table()
        self.master.after(0, _upd)

    def _stop(self):
        self.stop_flag.set()
        self._log("[STOPPED] User terminated scan", "warning")
        # Re-enable START after a brief delay to let threads clean up
        self.master.after(500, lambda: self._scan_done())
        self._log("Stopping scan...", "warning")
        self.stat_status.set("STOPPED")

    def _scan_done(self):
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress["value"] = self.progress.cget("maximum")
        
        # Different completion message
        msg = "Acquisition complete." if self.mode_var.get() == 1 else "Scan complete."
        self.prog_lbl.config(text=msg)
        self.stat_status.set("DONE")
        self.stat_keys.set(str(len(self.results)))
        valid = sum(1 for r in self.results
                    if r.get("Validation") == "Valid (mod-11)")
        self.stat_valid.set(str(valid))
        self._refresh_table()
        self._log(
            f"═══ SCAN COMPLETE ═══   {len(self.results)} key(s)  "
            f"|  {valid} valid (mod-11)", "success")

    # ── Table ──────────────────────────────────────────────────────────────
    def _refresh_table(self):
        self._clear_table()
        for i, row in enumerate(self.results, 1):
            v = row.get("Validation", "")
            if v.startswith("Valid"):
                tag = "valid"
            elif v.startswith("Pattern"):
                tag = "pattern"
            else:
                tag = "even" if i % 2 == 0 else "odd"
            self.table.insert("", "end", tags=(tag,), values=(
                i,
                row.get("Key Type",        ""),
                row.get("Validation",      ""),
                row.get("BitLocker Key",   ""),
                row.get("Memory Offset",   ""),
                row.get("Encoding",        ""),
                row.get("Recovery Key ID", ""),
            ))
        self.table.tag_configure("valid",   background="#1a3a2a",
                                 foreground=T["ACCENT2"])
        self.table.tag_configure("pattern", background="#3a2d1a",
                                 foreground=T["ACCENT3"])
        self.table.tag_configure("even",    background=T["BG_INPUT"])
        self.table.tag_configure("odd",     background=T["BG_CARD"])

    def _clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def _on_result_click(self, event):
        """Show detail viewer when result row is clicked."""
        sel = self.table.selection()
        if not sel:
            return
        idx = int(sel[0]) - 1
        if idx < 0 or idx >= len(self.results):
            return
        row = self.results[idx]
        self._show_result_detail(row, idx + 1)

    def _show_result_detail(self, row, num):
        """Display result details in a popup window."""
        dlg = tk.Toplevel(self.master)
        dlg.title(f"BitLocker Key Details — #{num}")
        dlg.geometry("600x400")
        dlg.configure(bg=T["BG_DARK"])
        dlg.transient(self.master)
        dlg.grab_set()

        # Header
        hdr = tk.Frame(dlg, bg=T["BG_PANEL"], height=60)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"Key #{num} Details",
                 bg=T["BG_PANEL"], fg=T["ACCENT2"],
                 font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=15, pady=10)

        # Scrollable content
        canvas = tk.Canvas(dlg, bg=T["BG_DARK"], highlightthickness=0)
        scroll = ttk.Scrollbar(dlg, orient="vertical", command=canvas.yview)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scroll.set)

        frame = tk.Frame(canvas, bg=T["BG_CARD"])
        canvas.create_window((0, 0), window=frame, anchor="nw")

        # Detail fields
        details = [
            ("Key Type", row.get("Key Type", "N/A")),
            ("Validation", row.get("Validation", "N/A")),
            ("BitLocker Key", row.get("BitLocker Key", "N/A")),
            ("Memory Offset", row.get("Memory Offset", "N/A")),
            ("Encoding", row.get("Encoding", "N/A")),
            ("Recovery Key ID", row.get("Recovery Key ID", "N/A")),
        ]

        for label, value in details:
            lf = tk.Frame(frame, bg=T["BG_CARD"])
            lf.pack(fill="x", padx=12, pady=8)
            tk.Label(lf, text=f"{label}:",
                     bg=T["BG_CARD"], fg=T["ACCENT1"],
                     font=("Segoe UI", 9, "bold")).pack(anchor="w")
            vf = tk.Frame(lf, bg=T["BG_INPUT"], relief=tk.FLAT, bd=1)
            vf.pack(fill="x", pady=(4, 0))
            txt = tk.Text(vf, height=2 if len(str(value)) > 60 else 1,
                         width=60, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                         font=("Consolas", 9), relief=tk.FLAT, bd=2,
                         wrap="word")
            txt.pack(fill="both", expand=True, padx=4, pady=4)
            txt.insert("1.0", str(value))
            txt.config(state=tk.DISABLED)

        frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        # Buttons
        btn_frame = tk.Frame(dlg, bg=T["BG_PANEL"])
        btn_frame.pack(fill="x", side="bottom", padx=12, pady=10)
        
        def copy_key():
            key = row.get("BitLocker Key", "")
            if key:
                self.master.clipboard_clear()
                self.master.clipboard_append(key)
                messagebox.showinfo("Copied", "Key copied to clipboard!")

        make_btn(btn_frame, "Copy Key", copy_key, T["ACCENT2"],
                padx=12, pady=6).pack(side="left", padx=4)
        make_btn(btn_frame, "Close", dlg.destroy, T["ACCENT4"],
                padx=12, pady=6).pack(side="right", padx=4)

    def _copy_key(self, event):
        sel = self.table.selection()
        if not sel:
            return
        vals = self.table.item(sel[0])["values"]
        if vals and len(vals) >= 4:
            self.master.clipboard_clear()
            self.master.clipboard_append(str(vals[3]))
            self._log(f"Copied to clipboard: {vals[3]}", "dim")

    # ── Console ────────────────────────────────────────────────────────────
    def _log(self, msg, level="info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {msg}\n", level)
        self.console.see(tk.END)

    def _clear_console(self):
        self.console.delete("1.0", tk.END)

    # ── Export ─────────────────────────────────────────────────────────────
    def _export(self):
        if not self.results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        
        # Get project root (parent of ui folder)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Create filename with timestamp
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"BitLocker_Results_{ts}.txt"
        filepath = os.path.join(project_root, filename)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("BitLocker Key Finder v1.1 — Results Export\n")
                f.write("=" * 80 + "\n\n")
                
                # Header info
                f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
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
                        f.write(f"    Memory Offset:   {row.get('Memory Offset', 'N/A')}\n")
                        f.write(f"    Encoding:        {row.get('Encoding', 'N/A')}\n")
                        f.write(f"    Recovery ID:     {row.get('Recovery Key ID', 'N/A')}\n")
                        f.write(f"    Key Type:        {row.get('Key Type', 'N/A')}\n")
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
        self.stat_keys.set("0")
        self.stat_valid.set("0")
        self.stat_status.set("IDLE")
        self.progress["value"] = 0
        self.prog_lbl.config(text="Ready")
        self._log("Cleared. Ready for new scan.", "dim")

    # ── Export functions ───────────────────────────────────────────────────────
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
                'scan_type': 'Live RAM Extraction',
                'scan_location': 'Physical RAM',
                'start_time': getattr(self, 'scan_start_time', 'N/A'),
                'end_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_size': f"{self.stat_total.get()} GB" if hasattr(self, 'stat_total') else 'N/A',
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
            success = generate_ram_report(filename, case_info, findings, summary, stats)
            if success:
                messagebox.showinfo("Success", f"PDF Report saved:\n{filename}")
                self._log(f"PDF exported to: {filename}", "info")
            else:
                messagebox.showerror("Error", "Failed to generate PDF.")
        except Exception as e:
            messagebox.showerror("PDF Export Error", f"{str(e)}")
            self._log(f"PDF export failed: {str(e)}", "error")
    
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
                f.write(f"Scan Type: Live RAM Extraction\n")
                f.write(f"Total Keys Found: {len(self.results)}\n\n")
                
                # Results
                f.write("RESULTS:\n")
                f.write("-" * 80 + "\n")
                for i, result in enumerate(self.results, 1):
                    f.write(f"Key #{i}\n")
                    f.write(f"BitLocker Key: {result.get('BitLocker Key', 'N/A')}\n")
                    f.write(f"Validation: {result.get('Validation', 'N/A')}\n")
                    f.write(f"Encoding: {result.get('Encoding', 'N/A')}\n")
                    f.write(f"Memory Offset: {result.get('Memory Offset', 'N/A')}\n")
                    f.write(f"Recovery Key ID: {result.get('Recovery Key ID', 'N/A')}\n")
                    f.write("-" * 80 + "\n")
            
            messagebox.showinfo("Success", f"Results saved to:\n{filename}")
            self._log(f"Text file exported: {filename}", "info")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed:\n{str(e)}")

    # ── Navigation ─────────────────────────────────────────────────────────
    def _go_back(self):
        if self.scanning:
            if not messagebox.askyesno("Scan Running",
                                       "Stop scan and go back?"):
                return
            self.stop_flag.set()
        self.on_back()