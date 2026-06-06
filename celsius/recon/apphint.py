"""Hostname → likely-service hints.

Self-hosters name subdomains after the app (cloud→Nextcloud, s3→MinIO,
uptime→Uptime Kuma, znc→ZNC). When direct fingerprinting comes up empty — the app
sits behind an auth gate, is down (502), or the host returns a bare 404 — the
hostname itself is still a strong hint about what's *meant* to run there. This is a
naming convention, not proof, so hints are low-confidence and clearly labelled.

Only apply to REAL hosts (the scanned target / CT-verified subdomains), never to
wildcard-resolved brute-force names — those resolve but run nothing.
"""

from __future__ import annotations

# leftmost-label (and a few common aliases) -> likely app(s)
APP_HINTS: dict[str, str] = {
    "auth": "Authelia / Authentik / Keycloak (SSO)",
    "sso": "Authelia / Authentik / Keycloak (SSO)",
    "login": "SSO / auth portal",
    "cloud": "Nextcloud", "nextcloud": "Nextcloud", "nc": "Nextcloud",
    "collabora": "Collabora Online", "office": "Collabora / OnlyOffice",
    "wopi": "Collabora/Office WOPI host",
    "s3": "MinIO / Garage (S3 storage)", "minio": "MinIO", "garage": "Garage",
    "s3ui": "MinIO Console", "console": "MinIO Console",
    "uptime": "Uptime Kuma", "status": "Uptime Kuma / status page",
    "grafana": "Grafana", "prometheus": "Prometheus", "metrics": "Prometheus/Grafana",
    "git": "Gitea / Forgejo / GitLab", "gitea": "Gitea", "forgejo": "Forgejo",
    "gitlab": "GitLab", "code": "Gitea / code-server",
    "vault": "Vaultwarden", "vaultwarden": "Vaultwarden", "bitwarden": "Vaultwarden",
    "passwords": "Vaultwarden", "bw": "Vaultwarden",
    "mail": "Mailserver (Postfix/Dovecot/Mailcow)", "webmail": "Roundcube / webmail",
    "roundcube": "Roundcube", "smtp": "Mailserver", "imap": "Mailserver",
    "znc": "ZNC (IRC bouncer)", "irc": "IRC / TheLounge",
    "pangolin": "Pangolin (reverse proxy / tunnel)", "traefik": "Traefik",
    "npm": "Nginx Proxy Manager", "proxy": "Reverse proxy",
    "jellyfin": "Jellyfin", "plex": "Plex", "emby": "Emby", "media": "Media server",
    "request": "Overseerr / Jellyseerr", "overseerr": "Overseerr", "jellyseerr": "Jellyseerr",
    "radarr": "Radarr", "sonarr": "Sonarr", "lidarr": "Lidarr", "prowlarr": "Prowlarr",
    "bazarr": "Bazarr", "readarr": "Readarr", "tautulli": "Tautulli",
    "qbittorrent": "qBittorrent", "qbit": "qBittorrent", "deluge": "Deluge",
    "transmission": "Transmission", "sabnzbd": "SABnzbd",
    "immich": "Immich", "photos": "Immich / PhotoPrism", "photoprism": "PhotoPrism",
    "paperless": "Paperless-ngx", "docs": "Paperless / docs",
    "bookstack": "BookStack", "wiki": "BookStack / Wiki.js", "outline": "Outline",
    "freshrss": "FreshRSS", "miniflux": "Miniflux", "rss": "FreshRSS / Miniflux",
    "readeck": "Readeck", "wallabag": "Wallabag",
    "vikunja": "Vikunja", "tasks": "Vikunja", "todo": "Vikunja",
    "linkding": "Linkding", "bookmarks": "Linkding", "hoarder": "Hoarder",
    "obsidian": "Obsidian LiveSync (CouchDB)", "notes": "Notes app", "memos": "Memos",
    "home": "Home Assistant", "ha": "Home Assistant", "hass": "Home Assistant",
    "adguard": "AdGuard Home", "pihole": "Pi-hole", "dns": "DNS / Pi-hole",
    "navidrome": "Navidrome", "music": "Navidrome", "audiobookshelf": "Audiobookshelf",
    "calibre": "Calibre-Web", "books": "Calibre / Kavita", "kavita": "Kavita", "komga": "Komga",
    "syncthing": "Syncthing", "filebrowser": "File Browser", "files": "File Browser / Nextcloud",
    "gotify": "Gotify", "ntfy": "ntfy", "mealie": "Mealie",
    "dashy": "Dashy", "homer": "Homer", "heimdall": "Heimdall", "dashboard": "Dashboard",
    "portainer": "Portainer", "uptimekuma": "Uptime Kuma",
}


def hint_from_hostname(host: str) -> str | None:
    """Likely service for the host's leftmost label, or None if no convention matches."""
    label = (host or "").split(".")[0].lower().strip()
    return APP_HINTS.get(label)
