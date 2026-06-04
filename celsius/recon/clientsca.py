"""Client-side software composition analysis.

A live website rarely hands over its source — but it *does* ship its front-end
libraries. This module spots well-known JS libraries and their versions from the
loaded script URLs (CDN paths, versioned filenames) and from version banners in
the script bodies, then hands them to sca.audit_deps() for an OSV.dev lookup.

The result: "your site loads jQuery 1.12.4 → known XSS CVEs" — observable without
any source access, and where a lot of real website risk actually lives.

Precision over recall: only an allow-list of known libraries is reported, so we
don't OSV-query every "app-1.2.3.js" bundle name.
"""

from __future__ import annotations

import re

from ..sca import Dep

# Known front-end libraries -> their OSV npm package name. Keys are the names as
# they appear in CDN paths / filenames / banners (lower-cased); values are the
# canonical npm package used for the OSV query.
_NPM = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jqueryui": "jquery-ui",
    "bootstrap": "bootstrap", "twitter-bootstrap": "bootstrap",
    "lodash": "lodash", "underscore": "underscore",
    "moment": "moment", "angular": "angular", "angularjs": "angular",
    "vue": "vue", "react": "react", "react-dom": "react-dom",
    "axios": "axios", "handlebars": "handlebars", "knockout": "knockout",
    "backbone": "backbone", "d3": "d3", "chart.js": "chart.js", "chartjs": "chart.js",
    "swiper": "swiper", "select2": "select2", "dompurify": "dompurify",
    "three": "three", "marked": "marked", "mustache": "mustache",
    "video.js": "video.js", "videojs": "video.js", "tinymce": "tinymce",
    "ckeditor": "ckeditor", "summernote": "summernote", "prismjs": "prismjs",
    "highlight.js": "highlight.js", "highlightjs": "highlight.js",
    "next": "next", "nuxt": "nuxt", "ember-source": "ember-source",
    # cdnjs / alternate names -> npm
    "lodash.js": "lodash", "underscore.js": "underscore", "moment.js": "moment",
    "angular.js": "angular", "vue.js": "vue", "react.js": "react",
    "twitter-bootstrap": "bootstrap", "axios.js": "axios",
}

_VER = r"(?P<ver>\d+\.\d+(?:\.\d+)?)"
# CDN URL forms that embed the npm name + version explicitly (high precision).
_CDN = [
    re.compile(r"/npm/(?P<name>@?[\w.-]+(?:/[\w.-]+)?)@" + _VER, re.I),                 # jsdelivr/unpkg npm
    re.compile(r"unpkg\.com/(?P<name>@?[\w.-]+(?:/[\w.-]+)?)@" + _VER, re.I),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/(?P<name>[\w.-]+)/" + _VER, re.I),
    re.compile(r"/ajax/libs/(?P<name>[\w.-]+)/" + _VER, re.I),
    # generic versioned path "/<name>/<x.y.z>/" (e.g. bootstrapcdn /bootstrap/3.4.1/);
    # the allow-list filters out non-library path segments.
    re.compile(r"/(?P<name>[a-z][\w.-]+)/" + _VER + r"/", re.I),
]
# Versioned filename, e.g. jquery-3.5.1.min.js, bootstrap.3.4.1.js
_FILE = re.compile(r"/(?P<name>[a-z][a-z0-9.\-]*?)[-.@]" + _VER + r"(?:[.\-][\w.]*)?\.js", re.I)
# Version banners inside script bodies (only for libs whose banner is distinctive).
_BANNERS = [
    ("jquery", re.compile(r"jQuery(?: JavaScript Library)? v" + _VER, re.I)),
    ("bootstrap", re.compile(r"Bootstrap v" + _VER, re.I)),
    ("moment", re.compile(r"moment(?:\.js)?[^\n]{0,40}?version\s*:?\s*" + _VER, re.I)),
    ("vue", re.compile(r"Vue\.js v" + _VER, re.I)),
    ("angular", re.compile(r"AngularJS v" + _VER, re.I)),
    ("handlebars", re.compile(r"Handlebars v" + _VER, re.I)),
    ("d3", re.compile(r"d3 v" + _VER, re.I)),
]


def _norm(name: str) -> str:
    return _NPM.get((name or "").strip().lower().lstrip("@"))


def detect_libraries(urls, sources: dict, *, pages: dict | None = None) -> list[Dep]:
    """Return Deps (ecosystem 'npm') for known client-side libraries + versions
    found in `urls` (script/CDN URLs), `sources` ({url: body}) and `pages` HTML."""
    found: dict[tuple, Dep] = {}

    def add(raw_name: str, ver: str):
        npm = _norm(raw_name)
        if npm and ver:
            found.setdefault((npm, ver), Dep("npm", npm, ver, "<client-side>"))

    haystack_urls = set(urls or [])
    for body in (pages or {}).values():
        # also catch <script src=...> and CDN refs embedded in HTML
        haystack_urls.update(re.findall(r"""['"](https?://[^'"\s]+?\.js[^'"\s]*)['"]""", body or ""))

    for u in haystack_urls:
        for pat in _CDN:
            m = pat.search(u)
            if m:
                add(m.group("name"), m.group("ver"))
        m = _FILE.search(u)
        if m:
            add(m.group("name"), m.group("ver"))

    for body in (sources or {}).values():
        for name, pat in _BANNERS:
            m = pat.search(body or "")
            if m:
                add(name, m.group("ver"))

    return list(found.values())
