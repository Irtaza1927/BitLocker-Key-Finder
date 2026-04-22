"""
Settings, Help, and About screens for BitLocker Key Finder v1.2
Uses GLOBAL theme from theme_config - changes apply to ALL screens
"""

import tkinter as tk
import theme_config  # Import global theme config

class SettingsScreen:
    """Settings Panel - Theme control (applies globally)"""
    def __init__(self, master, on_back, on_save=None):
        self.master = master
        self.on_back = on_back
        self.on_save = on_save
        self.frame = tk.Frame(master, bg="#000000")  # Placeholder
        self.theme_var = tk.IntVar(value=theme_config.current_theme)
        
    def _apply_theme(self):
        """Apply selected theme globally and refresh screen"""
        # Save theme to global config
        theme_config.set_theme(self.theme_var.get())
        
        # Rebuild screen with new theme
        self.frame.destroy()
        self.frame = tk.Frame(self.master, bg="#000000")
        self.build().pack(fill="both", expand=True)
        
    def build(self):
        """Build settings UI"""
        T = theme_config.get_current_theme()
        
        # Header
        header = tk.Frame(self.frame, bg=T["BG_PANEL"])
        header.pack(fill="x")
        
        tk.Label(header, text="⚙️  SETTINGS", 
                bg=T["BG_PANEL"], fg=T["ACCENT1"],
                font=T["FONT_HEADER"], padx=10, pady=14).pack(side="left")
        
        tk.Button(header, text="← Back", command=self.on_back,
                 bg=T["ACCENT1"], fg=T["BG_DARK"], 
                 font=T["FONT_SMALL"], relief=tk.FLAT, padx=15, pady=8).pack(side="right", padx=10, pady=10)
        
        tk.Frame(header, bg=T["ACCENT1"], height=2).pack(fill="x")
        
        # Content
        content = tk.Frame(self.frame, bg=T["BG_DARK"])
        content.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Theme Section (ONLY SETTING)
        tk.Label(content, text="THEME",
                bg=T["BG_DARK"], fg=T["ACCENT1"],
                font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(10, 15))
        
        theme_frame = tk.Frame(content, bg=T["BG_DARK"])
        theme_frame.pack(anchor="w", pady=10)
        
        tk.Radiobutton(theme_frame, text="◉ Dark Professional (Recommended)",
                      variable=self.theme_var, value=1,
                      bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                      selectcolor=T["ACCENT1"], activebackground=T["BG_CARD"],
                      font=T["FONT_BODY"],
                      command=self._apply_theme).pack(anchor="w", pady=8)
        
        tk.Radiobutton(theme_frame, text="○ High Contrast",
                      variable=self.theme_var, value=2,
                      bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                      selectcolor=T["ACCENT1"], activebackground=T["BG_CARD"],
                      font=T["FONT_BODY"],
                      command=self._apply_theme).pack(anchor="w", pady=8)
        
        tk.Label(theme_frame, text="(Theme applies to ALL screens immediately)",
                bg=T["BG_DARK"], fg=T["TEXT_DIM"],
                font=T["FONT_SMALL"]).pack(anchor="w", pady=(10, 0))
        
        # Buttons
        button_frame = tk.Frame(content, bg=T["BG_DARK"])
        button_frame.pack(fill="x", pady=(40, 0))
        
        tk.Button(button_frame, text="Save & Close",
                 bg=T["ACCENT1"], fg=T["BG_DARK"],
                 font=T["FONT_BODY"], relief=tk.FLAT, padx=20, pady=10,
                 command=self.on_back).pack(side="left", padx=5)
        
        return self.frame


class HelpScreen:
    """Help & Documentation"""
    def __init__(self, master, on_back):
        self.master = master
        self.on_back = on_back
        self.frame = tk.Frame(master, bg="#000000")
        
    def build(self):
        """Build help UI"""
        T = theme_config.get_current_theme()
        
        # Header
        header = tk.Frame(self.frame, bg=T["BG_PANEL"])
        header.pack(fill="x")
        
        tk.Label(header, text="❓  HELP & DOCUMENTATION", 
                bg=T["BG_PANEL"], fg=T["ACCENT1"],
                font=T["FONT_HEADER"], padx=10, pady=14).pack(side="left")
        
        tk.Button(header, text="← Back", command=self.on_back,
                 bg=T["ACCENT1"], fg=T["BG_DARK"], 
                 font=T["FONT_SMALL"], relief=tk.FLAT, padx=15, pady=8).pack(side="right", padx=10, pady=10)
        
        tk.Frame(header, bg=T["ACCENT1"], height=2).pack(fill="x")
        
        # Content
        content = tk.Frame(self.frame, bg=T["BG_DARK"])
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        help_text = """
📖 USER GUIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Live RAM Extraction: Acquires full physical RAM and scans for BitLocker keys
• Partition Scan: Scans disk/partition for BitLocker recovery files
• Double-click any result to copy key to clipboard

🔐 BITLOCKER BASICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Recovery keys are 48-digit passwords (6-6-6-6-6-6-6-6 format)
• Valid (mod-11): Passes Microsoft's checksum algorithm
• Pattern-only: Matches format but fails validation
• Memory Offset: Shows where in RAM the key was found

🎯 QUICK START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Enable BitLocker on test drive
2. Save recovery key to file
3. Open BitLocker Key Finder
4. Select "Live RAM Extraction"
5. Click [Browse] and choose output location
6. Click [START] while encryption is running
7. Wait for scan to complete
8. Check FOUND KEYS table for results

❓ FAQ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Q: Why are no keys found?
A: BitLocker key only in RAM while system is running.

Q: What does "Valid (mod-11)" mean?
A: Passes Microsoft checksum validation. High confidence it's real.

Q: What is Memory Offset?
A: Exact location in RAM where key was found (hexadecimal address).
        """
        
        text_widget = tk.Text(content, height=20, width=80,
                             bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                             font=T["FONT_CONSOLE"], relief=tk.FLAT,
                             padx=10, pady=10, insertbackground=T["ACCENT1"],
                             wrap=tk.WORD, bd=0)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert(1.0, help_text)
        text_widget.config(state=tk.DISABLED)
        
        return self.frame


class AboutScreen:
    """About Screen"""
    def __init__(self, master, on_back):
        self.master = master
        self.on_back = on_back
        self.frame = tk.Frame(master, bg="#000000")
        
    def build(self):
        """Build about UI"""
        T = theme_config.get_current_theme()
        
        # Header
        header = tk.Frame(self.frame, bg=T["BG_PANEL"])
        header.pack(fill="x")
        
        tk.Label(header, text="ℹ️  ABOUT", 
                bg=T["BG_PANEL"], fg=T["ACCENT1"],
                font=T["FONT_HEADER"], padx=10, pady=14).pack(side="left")
        
        tk.Button(header, text="← Back", command=self.on_back,
                 bg=T["ACCENT1"], fg=T["BG_DARK"], 
                 font=T["FONT_SMALL"], relief=tk.FLAT, padx=15, pady=8).pack(side="right", padx=10, pady=10)
        
        tk.Frame(header, bg=T["ACCENT1"], height=2).pack(fill="x")
        
        # Content
        content = tk.Frame(self.frame, bg=T["BG_DARK"])
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        about_text = """
🔐 BitLocker Key Finder v1.0

Advanced Forensic Recovery Tool for BitLocker Encryption

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DEVELOPED BY:
Team: FAST-NUCES Digital Forensics
Members:
  • Muhammad Ammar Shahid (23I-2125)
  • Irtaza Zahid (23i-2096)
  • Usman Khan (23I-2069)
  • Shaheer Shaban (23I-2040)

Semester 6 | BS Cybersecurity
FAST-NUCES Islamabad

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERSION:
v1.0 (April 2026) - Initial Release

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMING SOON:
✓ Enhanced Dashboard
✓ Advanced Filtering & Search
✓ Network Export Options
✓ Custom Signatures
✓ Integration APIs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CONTACT:
📧 i232096@nu.edu.pk

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DISCLAIMER:
This tool is designed for authorized forensic investigations
and educational purposes only. Unauthorized access to
encrypted systems is illegal.
        """
        
        text_widget = tk.Text(content, height=20, width=80,
                             bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
                             font=T["FONT_CONSOLE"], relief=tk.FLAT,
                             padx=10, pady=10, insertbackground=T["ACCENT1"],
                             wrap=tk.WORD, bd=0)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert(1.0, about_text)
        text_widget.config(state=tk.DISABLED)
        
        return self.frame