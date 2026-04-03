THEMES = {
    "dark": {
        "BG": "#0d0f14", "BG2": "#13161e", "BG3": "#1a1e2a",
        "PANEL": "#1e2230", "BORDER": "#2a2f42",
        "FG": "#cdd6f4", "FG_DIM": "#6e738d",
        "ACCENT": "#89b4fa", "GREEN": "#a6e3a1", "RED": "#f38ba8",
        "YELLOW": "#f9e2af", "PURPLE": "#cba6f7", "TEAL": "#94e2d5",
        "ORANGE": "#fab387", "PINK": "#f5c2e7",
        "MPL_BG": "#13161e", "MPL_FG": "#cdd6f4",
    },
    "light": {
        "BG": "#eff1f5", "BG2": "#e6e9ef", "BG3": "#dce0e8",
        "PANEL": "#ccd0da", "BORDER": "#bcc0cc",
        "FG": "#4c4f69", "FG_DIM": "#9ca0b0",
        "ACCENT": "#1e66f5", "GREEN": "#40a02b", "RED": "#d20f39",
        "YELLOW": "#df8e1d", "PURPLE": "#8839ef", "TEAL": "#179299",
        "ORANGE": "#fe640b", "PINK": "#ea76cb",
        "MPL_BG": "#e6e9ef", "MPL_FG": "#4c4f69",
    }
}

T = THEMES["dark"]

def svc_color(svc):
    return {
        "HTTP": T["ACCENT"], "SSH": T["GREEN"], "FTP": T["ORANGE"],
        "TELNET": T["YELLOW"], "SMTP": T["PURPLE"], "MYSQL": T["TEAL"],
        "TARPIT": T["RED"]
    }.get(svc, T["FG"])