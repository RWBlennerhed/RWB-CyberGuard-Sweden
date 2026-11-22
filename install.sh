#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.local/share/rwb-cyberguard-alpha6"
DESKTOP="$HOME/.local/share/applications/rwb-cyberguard-alpha6.desktop"
ICON_SOURCE="$SCRIPT_DIR/rwb_cyberguard_icon_256.png"
ICON_DEST="$HOME/.local/share/icons/hicolor/256x256/apps/rwb-cyberguard-alpha6.png"
mkdir -p "$DEST" "$(dirname "$DESKTOP")" "$(dirname "$ICON_DEST")"
python3 -m py_compile "$SCRIPT_DIR/cyberguard_v3_0_alpha6.py"
if [[ -f "$DEST/cyberguard_v3_0_alpha6.py" ]]; then
    BACKUP_DIR="$HOME/RWB-CyberGuard/Sakerhetskopior/Installationer"
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    BACKUP_FILE="$BACKUP_DIR/cyberguard_alpha6_${TIMESTAMP}.py"

    cp -p "$DEST/cyberguard_v3_0_alpha6.py" "$BACKUP_FILE"
    echo "Säkerhetskopia skapad: $BACKUP_FILE"
fi
cp "$SCRIPT_DIR/cyberguard_v3_0_alpha6.py" "$DEST/cyberguard_v3_0_alpha6.py"
if [[ -f "$ICON_SOURCE" ]]; then
    cp "$ICON_SOURCE" "$ICON_DEST"
elif [[ -f "$HOME/.local/share/icons/hicolor/256x256/apps/rwb-cyberguard.png" ]]; then
    cp "$HOME/.local/share/icons/hicolor/256x256/apps/rwb-cyberguard.png" "$ICON_DEST"
else
    echo "VARNING: Ingen ikon hittades; använd ~/RWB-CyberGuard/Ikoner/rwb_cyberguard_icon_256.png" >&2
fi
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=RWB CyberGuard Sweden 3.0 Alpha 6
Comment=Passiv webbplatskontroll med lokal webbadresshantering
Exec=/usr/bin/python3 $DEST/cyberguard_v3_0_alpha6.py
Icon=$ICON_DEST
Terminal=false
Categories=Development;Utility;
StartupNotify=false
StartupWMClass=RWB-CyberGuard-Alpha6
EOF
chmod 644 "$DESKTOP"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
fi
echo "Alpha 6 installerad separat från Alpha 5."
echo "Starta från ChromeOS programmeny: RWB CyberGuard Sweden 3.0 Alpha 6"
