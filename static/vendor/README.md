# Bundled browser libraries

The dashboard serves these itself, so the administrator's browser needs nothing
from the internet. Each file is the published one, byte for byte; `SHA256SUMS`
lists them and `tests/test_vendor.py` checks them.

| File | What | Version | Licence | Taken from |
|---|---|---|---|---|
| `tailwindcss-3.4.17.js` | Tailwind CSS (in-browser build) | 3.4.17 | MIT | `https://cdn.tailwindcss.com/3.4.17` (the newest in-browser build of v3; v4 is a different framework) |
| `chart-4.6.1.umd.js` | Chart.js | 4.6.1 | MIT | npm `chart.js@4.6.1`, `dist/chart.umd.js` |
| `xlsx-0.20.3.full.min.js` | SheetJS (Excel export) | 0.20.3 | Apache-2.0 | `https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz`, `dist/xlsx.full.min.js` (SheetJS publishes releases after 0.18.5 only on its own CDN) |
| `jspdf-4.2.1.umd.min.js` | jsPDF (PDF export) | 4.2.1 | MIT | npm `jspdf@4.2.1`, `dist/jspdf.umd.min.js` |
| `jspdf-autotable-5.0.9.min.js` | jsPDF AutoTable | 5.0.9 | MIT | npm `jspdf-autotable@5.0.9`, `dist/jspdf.plugin.autotable.min.js` |
| `fonts/inter-*.woff2` | Inter (variable) | fontsource 5.3.0 | OFL-1.1 | npm `@fontsource-variable/inter@5.3.0` |
| `fonts/jetbrains-mono-*.woff2` | JetBrains Mono (variable) | fontsource 5.3.0 | OFL-1.1 | npm `@fontsource-variable/jetbrains-mono@5.3.0` |

`fonts.css` is written for this project; the licence texts are in `licenses/`.

To update one: download the new file, check it against the publisher's checksum
(npm `dist.integrity`, or the SRI hash cdnjs publishes), put it here under a name
that carries the version, update the `<script>` tag in `templates/`, this table
and `SHA256SUMS`, and delete the old file.
