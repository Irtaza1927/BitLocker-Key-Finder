"""
Professional Themes for BitLocker Key Finder v1.2
Dark Professional + High Contrast modes
"""

THEME_DARK_PROFESSIONAL = {
    # Core Colors
    "BG_DARK": "#0a0a0a",          # Near black background
    "BG_PANEL": "#1a1a1a",         # Panel background
    "BG_CARD": "#252525",          # Card/section background
    "BG_INPUT": "#1a1a1a",         # Input field background
    
    # Text Colors
    "TEXT_PRIMARY": "#e0e0e0",      # Main text (light gray)
    "TEXT_LABEL": "#b0b0b0",        # Labels (medium gray)
    "TEXT_DIM": "#707070",          # Dimmed text (dark gray)
    "TEXT_HOVER": "#ffffff",        # Hover text (white)
    
    # Accent Colors (Forensic Green)
    "ACCENT1": "#00d084",           # Primary accent (forensic green)
    "ACCENT2": "#00e899",           # Secondary accent (bright green)
    "ACCENT3": "#009966",           # Tertiary accent (dark green)
    
    # Status Colors
    "SUCCESS": "#00d084",           # Valid keys (green)
    "WARNING": "#ffb84d",           # Pattern-only (orange)
    "ERROR": "#ff4444",             # Errors (red)
    "INFO": "#4fc3f7",              # Info (cyan)
    
    # Borders & Separators
    "BORDER": "#333333",            # Border color
    "SEPARATOR": "#2a2a2a",         # Separator line
    
    # Fonts
    "FONT_FAMILY": "Segoe UI",
    "FONT_HEADER": ("Segoe UI", 13, "bold"),
    "FONT_TITLE": ("Segoe UI", 14, "bold"),
    "FONT_BODY": ("Segoe UI", 10),
    "FONT_SMALL": ("Segoe UI", 9),
    "FONT_MONO": ("Consolas", 9),
    
    # Special
    "HIGHLIGHT": "#00d084",         # Highlight color
    "DISABLED": "#505050",          # Disabled state
    "SCROLLBAR": "#404040",         # Scrollbar color
}

THEME_HIGH_CONTRAST = {
    # Core Colors
    "BG_DARK": "#000000",           # Pure black background
    "BG_PANEL": "#1a1a1a",          # Panel background
    "BG_CARD": "#2a2a2a",           # Card/section background
    "BG_INPUT": "#1a1a1a",          # Input field background
    
    # Text Colors
    "TEXT_PRIMARY": "#ffffff",      # Main text (pure white)
    "TEXT_LABEL": "#e0e0e0",        # Labels (light gray)
    "TEXT_DIM": "#808080",          # Dimmed text (medium gray)
    "TEXT_HOVER": "#ffff00",        # Hover text (bright yellow)
    
    # Accent Colors (Bright Cyan)
    "ACCENT1": "#00ffff",           # Primary accent (bright cyan)
    "ACCENT2": "#66ffff",           # Secondary accent (light cyan)
    "ACCENT3": "#0099cc",           # Tertiary accent (dark cyan)
    
    # Status Colors
    "SUCCESS": "#00ff00",           # Valid keys (bright green)
    "WARNING": "#ffff00",           # Pattern-only (bright yellow)
    "ERROR": "#ff0000",             # Errors (bright red)
    "INFO": "#00ffff",              # Info (bright cyan)
    
    # Borders & Separators
    "BORDER": "#404040",            # Border color
    "SEPARATOR": "#333333",         # Separator line
    
    # Fonts
    "FONT_FAMILY": "Segoe UI",
    "FONT_HEADER": ("Segoe UI", 13, "bold"),
    "FONT_TITLE": ("Segoe UI", 14, "bold"),
    "FONT_BODY": ("Segoe UI", 10),
    "FONT_SMALL": ("Segoe UI", 9),
    "FONT_MONO": ("Consolas", 9),
    
    # Special
    "HIGHLIGHT": "#00ffff",         # Highlight color
    "DISABLED": "#606060",          # Disabled state
    "SCROLLBAR": "#505050",         # Scrollbar color
}

# Default theme (Dark Professional - most readable)
THEME_DEFAULT = THEME_DARK_PROFESSIONAL

# Theme registry
THEMES = {
    "Dark Professional": THEME_DARK_PROFESSIONAL,
    "High Contrast": THEME_HIGH_CONTRAST,
}

def get_theme(name: str = "Dark Professional"):
    """Get theme by name"""
    return THEMES.get(name, THEME_DEFAULT)

def list_themes():
    """List available themes"""
    return list(THEMES.keys())