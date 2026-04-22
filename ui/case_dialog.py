"""
case_dialog.py
─────────────────────────────────────────────────────────────────────────────
Dialog to collect case information for forensic reports
"""

import tkinter as tk
from tkinter import ttk, simpledialog
import theme_config


class CaseInfoDialog(tk.Toplevel):
    """Dialog to collect case information for PDF reports"""
    
    def __init__(self, parent, title="Case Information"):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x400")
        self.resizable(False, False)
        
        # Get current theme
        T = theme_config.get_current_theme()
        self.T = T
        
        self.configure(bg=T["BG_DARK"])
        self.result = None
        
        # Center window on parent
        self.transient(parent)
        self.grab_set()
        
        # Build UI
        self._build()
        
    def _build(self):
        """Build dialog UI"""
        T = self.T
        
        # Header
        header = tk.Frame(self, bg=T["BG_PANEL"])
        header.pack(fill="x", padx=0, pady=0)
        
        tk.Label(header, text="📋 Case Information",
                bg=T["BG_PANEL"], fg=T["ACCENT1"],
                font=("Segoe UI", 12, "bold"), padx=15, pady=10).pack(anchor="w")
        
        tk.Frame(header, bg=T["ACCENT1"], height=2).pack(fill="x")
        
        # Form frame
        form = tk.Frame(self, bg=T["BG_DARK"])
        form.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Case Number
        tk.Label(form, text="Case Number:",
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 5))
        
        self.case_number = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                                    font=("Segoe UI", 10), relief=tk.FLAT, bd=0)
        self.case_number.pack(fill="x", padx=5, pady=(0, 15), ipady=8)
        
        # Investigator Name
        tk.Label(form, text="Investigator Name:",
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 5))
        
        self.investigator = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                                     font=("Segoe UI", 10), relief=tk.FLAT, bd=0)
        self.investigator.pack(fill="x", padx=5, pady=(0, 15), ipady=8)
        
        # Device Name
        tk.Label(form, text="Device Name/ID:",
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 5))
        
        self.device_name = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                                    font=("Segoe UI", 10), relief=tk.FLAT, bd=0)
        self.device_name.pack(fill="x", padx=5, pady=(0, 15), ipady=8)
        
        # Evidence ID
        tk.Label(form, text="Evidence ID:",
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 5))
        
        self.evidence_id = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                                    font=("Segoe UI", 10), relief=tk.FLAT, bd=0)
        self.evidence_id.pack(fill="x", padx=5, pady=(0, 25), ipady=8)
        
        # Buttons
        button_frame = tk.Frame(form, bg=T["BG_DARK"])
        button_frame.pack(fill="x", pady=(20, 0))
        
        tk.Button(button_frame, text="Generate Report",
                 bg=T["ACCENT1"], fg=T["BG_DARK"],
                 font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                 padx=20, pady=10, cursor="hand2",
                 command=self._on_ok).pack(side="left", padx=5)
        
        tk.Button(button_frame, text="Cancel",
                 bg=T["ACCENT4"], fg=T["BG_DARK"],
                 font=("Segoe UI", 10), relief=tk.FLAT,
                 padx=20, pady=10, cursor="hand2",
                 command=self.destroy).pack(side="left", padx=5)
        
    def _on_ok(self):
        """Collect and return case information"""
        self.result = {
            'case_number': self.case_number.get() or "N/A",
            'investigator': self.investigator.get() or "N/A",
            'device_name': self.device_name.get() or "N/A",
            'evidence_id': self.evidence_id.get() or "N/A",
        }
        self.destroy()
    
    def get_info(self):
        """Get case information (wait for dialog to close)"""
        self.wait_window()
        return self.result