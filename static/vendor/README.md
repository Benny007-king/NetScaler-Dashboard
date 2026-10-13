# Bundled browser libraries

The dashboard serves these itself, so the administrator's browser needs nothing
from the internet. Each file is the published one, byte for byte; `SHA256SUMS`
lists them and `tests/test_vendor.py` checks them.

| File | What | Version | Licence | Taken from |
|---|---|---|---|---|
| `tailwindcss-3.4.17.js` | Tailwind CSS (in-browser build) | 3.4.17 | MIT | `https://cdn.tailwindcss.com/3.4.17` |
| `chart-4.5.1.umd.js` | Chart.js | 4.5.1 | MIT | npm `chart.js@4.5.1`, `dist/chart.umd.js` |
| `xlsx-0.18.5.full.min.js` | SheetJS (Excel export) | 0.18.5 | Apache-2.0 | cdnjs `xlsx/0.18.5/xlsx.full.min.js` |
| `jspdf-2.5.1.umd.min.js` | jsPDF (PDF export) | 2.5.1 | MIT | cdnjs `jspdf/2.5.1/jspdf.umd.min.js` |
| `jspdf-autotable-3.8.2.min.js` | jsPDF AutoTable | 3.8.2 | MIT | cdnjs `jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js` |
| `fonts/inter-*.woff2` | Inter (variable) | fontsource 5.3.0 | OFL-1.1 | npm `@fontsource-variable/inter@5.3.0` |
| `fonts/jetbrains-mono-*.woff2` | JetBrains Mono (variable) | fontsource 5.3.0 | OFL-1.1 | npm `@fontsource-variable/jetbrains-mono@5.3.0` |

`fonts.css` is written for this project; the licence texts are in `licenses/`.

To update one: download the new file, check it against the publisher's checksum
(npm `dist.integrity`, or the SRI hash cdnjs publishes), put it here under a name
that carries the version, update the `<script>` tag in `templates/`, this table
and `SHA256SUMS`, and delete the old file.
