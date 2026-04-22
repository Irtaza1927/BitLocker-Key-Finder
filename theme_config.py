"""
Global Theme Configuration
Shared across all screens in BitLocker Key Finder
"""

# Theme selection: 1 = Dark Professional, 2 = High Contrast
current_theme = 1

# Dark Professional Theme (DEFAULT)
THEME_DARK = {
    "BG_DARK":      "#13172b",
    "BG_PANEL":     "#1c2340",
    "BG_CARD":      "#232b4a",
    "BG_INPUT":     "#1a2038",
    "ACCENT1":      "#4fc3f7",   # sky blue
    "ACCENT2":      "#69db7c",   # soft green
    "ACCENT3":      "#ffa94d",   # amber
    "ACCENT4":      "#ff6b6b",   # coral red
    "ACCENT5":      "#cc99ff",   # lavender
    "TEXT_PRIMARY": "#dce3f0",
    "TEXT_DIM":     "#4a5568",
    "TEXT_LABEL":   "#8899aa",
    "BORDER":       "#2e3a5c",
    "FONT_TITLE":   ("Segoe UI", 20, "bold"),
    "FONT_HEADER":  ("Segoe UI", 11, "bold"),
    "FONT_BODY":    ("Segoe UI", 10),
    "FONT_SMALL":   ("Segoe UI", 9),
    "FONT_CONSOLE": ("Consolas", 9),
}

# High Contrast Theme
THEME_HIGH_CONTRAST = {
    "BG_DARK":      "#000000",
    "BG_PANEL":     "#1a1a1a",
    "BG_CARD":      "#2a2a2a",
    "BG_INPUT":     "#1a1a1a",
    "ACCENT1":      "#00ffff",   # bright cyan
    "ACCENT2":      "#00ff00",   # bright green
    "ACCENT3":      "#ffff00",   # bright yellow
    "ACCENT4":      "#ff0000",   # bright red
    "ACCENT5":      "#ff00ff",   # bright magenta
    "TEXT_PRIMARY": "#ffffff",
    "TEXT_DIM":     "#808080",
    "TEXT_LABEL":   "#e0e0e0",
    "BORDER":       "#404040",
    "FONT_TITLE":   ("Segoe UI", 20, "bold"),
    "FONT_HEADER":  ("Segoe UI", 11, "bold"),
    "FONT_BODY":    ("Segoe UI", 10),
    "FONT_SMALL":   ("Segoe UI", 9),
    "FONT_CONSOLE": ("Consolas", 9),
}

def get_current_theme():
    """Get the currently selected theme"""
    if current_theme == 2:
        return THEME_HIGH_CONTRAST
    return THEME_DARK

def set_theme(theme_id):
    """Set the theme (1=Dark Professional, 2=High Contrast)"""
    global current_theme
    current_theme = theme_id