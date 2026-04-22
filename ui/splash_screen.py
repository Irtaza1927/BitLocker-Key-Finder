"""
splash_screen.py
─────────────────────────────────────────────────────────────────────────────
Welcome/Splash screen shown on application startup
User presses ENTER to proceed to case information dialog
"""

import tkinter as tk
import theme_config

def show_splash(root, on_continue):
    """
    Display splash screen with press ENTER to continue
    
    Args:
        root: Tkinter root window
        on_continue: Callback function when user presses ENTER
    """
    
    # Clear window
    for w in root.winfo_children():
        w.destroy()
    
    # Get theme
    T = theme_config.get_current_theme()
    
    root.configure(bg=T["BG_DARK"])
    root.geometry("800x600")
    
    try:
        root.state("zoomed")
    except Exception:
        pass
    
    # Center frame
    center = tk.Frame(root, bg=T["BG_DARK"])
    center.pack(fill="both", expand=True)
    
    # Vertical center
    spacer1 = tk.Frame(center, bg=T["BG_DARK"])
    spacer1.pack(fill="both", expand=True)
    
    # Logo/Title section
    logo_frame = tk.Frame(center, bg=T["BG_DARK"])
    logo_frame.pack(fill="x", padx=20)
    
    # Lock emoji
    tk.Label(logo_frame, text="🔐",
            bg=T["BG_DARK"], fg=T["ACCENT1"],
            font=("Segoe UI", 80)).pack(pady=20)
    
    # Main title
    tk.Label(logo_frame, text="BitLocker Key Finder",
            bg=T["BG_DARK"], fg=T["ACCENT1"],
            font=("Segoe UI", 48, "bold")).pack(pady=5)
    
    # Version
    tk.Label(logo_frame, text="v1.0",
            bg=T["BG_DARK"], fg=T["TEXT_DIM"],
            font=("Segoe UI", 16)).pack()
    
    # Subtitle
    tk.Label(logo_frame, text="Digital Forensics Investigation Tool",
            bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
            font=("Segoe UI", 14)).pack(pady=10)
    
    # Divider line
    tk.Frame(logo_frame, bg=T["ACCENT1"], height=2).pack(fill="x", pady=20)
    
    # Institution info
    tk.Label(logo_frame, text="FAST-NUCES Islamabad",
            bg=T["BG_DARK"], fg=T["ACCENT2"],
            font=("Segoe UI", 12, "bold")).pack(pady=5)
    
    tk.Label(logo_frame, text="Semester 6 - Digital Forensics Project",
            bg=T["BG_DARK"], fg=T["TEXT_DIM"],
            font=("Segoe UI", 10)).pack(pady=(0, 40))
    
    # Features/Info section
    info_frame = tk.Frame(center, bg=T["BG_DARK"])
    info_frame.pack(fill="x", padx=60, pady=20)
    
    features = [
        "⚡ Live RAM Memory Extraction",
        "🔍 Partition & Disk Scanning",
        "🔐 BitLocker Recovery Key Recovery",
        "✓ mod-11 Checksum Validation",
    ]
    
    for feature in features:
        tk.Label(info_frame, text=feature,
                bg=T["BG_DARK"], fg=T["TEXT_PRIMARY"],
                font=("Segoe UI", 11), justify="left").pack(anchor="w", pady=4)
    
    # Bottom spacer
    spacer2 = tk.Frame(center, bg=T["BG_DARK"])
    spacer2.pack(fill="both", expand=True)
    
    # Footer with press ENTER message
    footer = tk.Frame(center, bg=T["BG_PANEL"], height=80)
    footer.pack(fill="x", side="bottom")
    footer.pack_propagate(False)
    
    tk.Label(footer, text="Press ENTER to Continue",
            bg=T["BG_PANEL"], fg=T["ACCENT1"],
            font=("Segoe UI", 14, "bold"), pady=15).pack()
    
    tk.Label(footer, text="or close window to exit",
            bg=T["BG_PANEL"], fg=T["TEXT_DIM"],
            font=("Segoe UI", 9)).pack()
    
    # Bind ENTER key
    root.bind("<Return>", lambda e: on_continue())
    root.focus()