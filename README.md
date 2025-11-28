# CODING 2.0 (OS) Shell

Developer‑friendly OS shell for local projects. Browse, edit, zip, mail, and manage files with an elegant desktop‑style UI. Built with PHP and designed for XAMPP/Apache environments.

## Overview
- Desktop‑style interface with wallpaper, header bar, and app widgets
- File manager with permission‑aware actions (view, edit, rename, zip/unzip, download)
- Terminal‑style command runner for quick operations
- Popup editor with safe write behavior
- Mailer for sending HTML/plain emails with clean headers
- Trash and cleaning tools for server artifacts
- Simple session login gate

## Features
- Customizable wallpaper with instant persistence via local storage
- Built‑in extensions: Browser, Server Info, and more
- Dark UI, Material Symbols icons, and smooth UX
- Optional APIs for diagnostics and content extraction (local use)

## Requirements
- PHP 7.4+ (PHP 8.x recommended)
- Web server (Apache/XAMPP recommended)
- Write permissions for the app directory (for editing/zipping)
- Internet access for remote wallpapers and icon fonts

## Installation
1. Download or clone the project into your web root (e.g. `htdocs/coding`).
2. Start your server (XAMPP/Apache).
3. Open `http://localhost/OScoding/` in the browser.

## Quick Start
- Login when prompted.
- Use the header bar to open apps (File Manager, Terminal, Editor, etc.).
- Change wallpaper using the wallpaper window; preferences persist automatically.

## Configuration
- Password: The default password is centralized at `test.php:3` in `$DEFAULT_OSCODING_PASSWORD`.
  - Change it there to set your own default.
- Wallpaper:
  - Defaults to type 13 preset.
  - Local storage keys: `coding.wallpaper` and `coding.wallpaper.type`.
  - You can also set a wallpaper via query: `?wallpaper=<http url or local filename>`.
## Tips
- Use the File Manager to edit files safely; the editor handles common write scenarios.
- Terminal‑style commands display output inline with color cues.
- Error handling adapts to dev vs production contexts.

## Security
- Intended for local development or protected environments.
- Avoid exposing the app publicly without additional authentication/hardening.
- Do not commit secrets; environment variables are respected where applicable.

## Support
- Website: `https://www.oscoding.vip`
- Telegram: `@Misterklio` (`https://t.me/Misterklio`)
- GitHub: `https://github.com/Misterklio`

## Credits
Coded with care by Mister klio.
