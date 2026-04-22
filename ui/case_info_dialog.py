"""
case_info_dialog.py
─────────────────────────────────────────────────────────────────────────────
Case information dialog shown after splash screen
Stores case info globally for all scan operations
"""

import tkinter as tk
from tkinter import messagebox
import theme_config

# Global case info storage
case_info = {
    'case_number': 'N/A',
    'investigator': 'N/A',
    'device_name': 'N/A',
    'notes': 'N/A',
}

def get_case_info():
    """Get stored case information"""
    return case_info

def set_case_info(info_dict):
    """Update case information"""
    global case_info
    case_info.update(info_dict)

def show_case_dialog(root, on_proceed, on_exit):
    """
    Display case information dialog
    
    Args:
        root: Tkinter root window
        on_proceed: Callback function when user clicks PROCEED
        on_exit: Callback function when user clicks EXIT
    """
    
    # Clear window
    for w in root.winfo_children():
        w.destroy()
    
    # Get theme
    T = theme_config.get_current_theme()
    
    root.configure(bg=T["BG_DARK"])
    root.geometry("700x650")
    
    try:
        root.state("zoomed")
    except Exception:
        pass
    
    # Center content
    center = tk.Frame(root, bg=T["BG_DARK"])
    center.pack(fill="both", expand=True, padx=60, pady=40)
    
    # Divider top
    tk.Frame(center, bg=T["ACCENT1"], height=3).pack(fill="x", pady=(0, 20))
    
    # Title
    tk.Label(center, text="🔐 CASE INFORMATION",
            bg=T["BG_DARK"], fg=T["ACCENT1"],
            font=("Segoe UI", 20, "bold")).pack(pady=(0, 5))
    
    tk.Label(center, text="Fill case details before proceeding",
            bg=T["BG_DARK"], fg=T["TEXT_DIM"],
            font=("Segoe UI", 10)).pack(pady=(0, 20))
    
    # Form frame
    form = tk.Frame(center, bg=T["BG_CARD"])
    form.pack(fill="both", expand=True, padx=20, pady=20)
    
    # Case Number
    tk.Label(form, text="Case Number *",
            bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
            font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15, pady=(15, 5))
    
    case_num = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                        font=("Segoe UI", 11), relief=tk.FLAT, bd=0,
                        insertbackground=T["ACCENT1"])
    case_num.pack(fill="x", padx=15, pady=(0, 15), ipady=10)
    case_num.insert(0, "")
    
    # Investigator
    tk.Label(form, text="Investigator Name *",
            bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
            font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15, pady=(0, 5))
    
    investigator = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                           font=("Segoe UI", 11), relief=tk.FLAT, bd=0,
                           insertbackground=T["ACCENT1"])
    investigator.pack(fill="x", padx=15, pady=(0, 15), ipady=10)
    investigator.insert(0, "")
    
    # Device Name
    tk.Label(form, text="Device / System Name *",
            bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
            font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15, pady=(0, 5))
    
    device = tk.Entry(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                     font=("Segoe UI", 11), relief=tk.FLAT, bd=0,
                     insertbackground=T["ACCENT1"])
    device.pack(fill="x", padx=15, pady=(0, 15), ipady=10)
    device.insert(0, "")
    
    # Notes
    tk.Label(form, text="Additional Notes (Optional)",
            bg=T["BG_CARD"], fg=T["TEXT_PRIMARY"],
            font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15, pady=(0, 5))
    
    notes = tk.Text(form, bg=T["BG_INPUT"], fg=T["TEXT_PRIMARY"],
                   font=("Segoe UI", 10), relief=tk.FLAT, bd=0,
                   height=5, width=40, insertbackground=T["ACCENT1"],
                   wrap="word")
    notes.pack(fill="both", expand=True, padx=15, pady=(0, 15), ipady=8)
    
    # Helper text
    tk.Label(form, text="* Required fields",
            bg=T["BG_CARD"], fg=T["TEXT_DIM"],
            font=("Segoe UI", 9)).pack(anchor="w", padx=15, pady=(0, 10))
    
    # Divider bottom
    tk.Frame(center, bg=T["ACCENT1"], height=3).pack(fill="x", pady=(20, 0))
    
    # Buttons frame
    btn_frame = tk.Frame(center, bg=T["BG_DARK"])
    btn_frame.pack(fill="x", pady=25)
    
    def on_proceed_click():
        """Handle PROCEED button click"""
        cn = case_num.get().strip()
        inv = investigator.get().strip()
        dev = device.get().strip()
        nt = notes.get("1.0", "end-1c").strip()
        
        # Validate required fields
        if not cn or not inv or not dev:
            messagebox.showwarning("Required Fields", 
                                  "Please fill: Case Number, Investigator, Device Name")
            return
        
        # Store case info globally
        set_case_info({
            'case_number': cn,
            'investigator': inv,
            'device_name': dev,
            'notes': nt if nt else 'N/A',
        })
        
        # Proceed to main menu
        on_proceed()
    
    # PROCEED button
    tk.Button(btn_frame, text="✓ PROCEED",
             bg=T["ACCENT2"], fg=T["BG_DARK"],
             font=("Segoe UI", 12, "bold"), relief=tk.FLAT,
             padx=40, pady=12, cursor="hand2",
             command=on_proceed_click).pack(side="left", padx=10)
    
    # EXIT button
    tk.Button(btn_frame, text="✕ EXIT",
             bg=T["ACCENT4"], fg="white",
             font=("Segoe UI", 12, "bold"), relief=tk.FLAT,
             padx=40, pady=12, cursor="hand2",
             command=on_exit).pack(side="left", padx=10)
    
    # Focus on first field
    case_num.focus()