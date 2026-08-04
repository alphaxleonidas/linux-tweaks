# linux-tweaks
Context menu scripts for Nautilus. And other Nautilus related tweaks.

# Detail


# Installation:

```
cd ~ 
git clone https://www.github.com/alphaxleonidas/linux-tweaks.git
cp -v ~/linux-tweaks/OpenWith/menuterminalgnome.desktop ~/.local/share/applications/
mkdir -p ~/.local/share/nautilus/scripts
cp -v ~/linux-tweaks/nautilus_scripts/* ~/.local/share/nautilus/scripts

chmod -v +x ~/.local/share/applications/menuterminalgnome.desktop
chmod -Rv +x ~/.local/share/nautilus/scripts/*
```

<!--
chmod -v +x ~/.local/share/nautilus/scripts/OpenTerminalHere
chmod -v +x ~/.local/share/nautilus/scripts/VirusTotalGnomeTerminal.sh
nano ~/.local/share/nautilus/scripts/VirusTotalGnomeTerminal.sh
-->


# MenuTerminal

Adds an option for Open With  using Gnome-terminal in Right Click Context Menu of Nautilus File Manager

```
cd ~/.local/share/applications
```

```
nano menuterminal.desktop
```

Add this to the file:

```
[Desktop Entry]
Version=1.0
Type=Application
Name=MenuTerminal
Comment=Open file/folder in GNOME Terminal
Exec=gnome-terminal --working-directory=%U .
Icon=utilities-terminal
Terminal=false
Categories=System;TerminalEmulator;
MimeType=text/plain;application/x-shellscript;inode/directory;
NoDisplay=false
StartupNotify=true
```

Now the Open With menu in Nautlius contains menuterminal which will open the terminal in that directory.


# Other Tweaks (System Wide) - Link to repos


[Commands](https://www.github.com/alphaxleonidas/commands)

[GPU-Stats-NVIDIA-GNOME](https://www.github.com/alphaxleonidas/GPU-Stats-NVIDIA-GNOME)

[GPU-Stats-NVIDIA-KDE](https://github.com/alphaxleonidas/GPU-Stats-NVIDIA-KDE)

[safe_rm-Bash-Script](https://www.github.com/alphaxleonidas/safe_rm-Bash-Script)

[safe_rm-Fish-Script](https://www.github.com/alphaxleonidas/safe_rm-Fish-Script)

[mpv](https://www.github.com/alphaxleonidas/mpv)


[HyperHeadset](https://github.com/alphaxleonidas/HyperHeadset)

