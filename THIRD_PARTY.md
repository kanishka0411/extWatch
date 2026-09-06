# Third-party components

ExtWatch is MIT licensed. It builds on:

| Component | License | Use |
| --- | --- | --- |
| [Qt 6](https://www.qt.io) | LGPL v3 (dynamically linked) | application framework, UI, SQLite driver, networking |
| [tree-sitter](https://github.com/tree-sitter/tree-sitter) and [tree-sitter-javascript](https://github.com/tree-sitter/tree-sitter-javascript) | MIT | parsing JavaScript for analysis and formatting |
| [dtl](https://github.com/cubicdaiya/dtl) | BSD 3-Clause | line diffs |
| [miniz](https://github.com/richgel999/miniz) | MIT | zip and CRX reading, zip export (vendored in `third_party/miniz`) |

Qt is loaded as shared libraries, so the LGPL's relinking requirement is met by the packaged
frameworks and DLLs; nothing in this repository is derived from Qt source.
