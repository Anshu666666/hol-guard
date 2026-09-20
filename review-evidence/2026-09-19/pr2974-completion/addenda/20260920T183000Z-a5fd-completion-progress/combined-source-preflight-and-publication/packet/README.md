# Exact combined-source preflight/publication preservation

This packet retains every original byte of the 17 files under completion-fixes-preflight plus the original driver, source staging record and publication receipt. It does not rerun or reinterpret those checks. The retained publication is a5fdde302aba2a06265c2e6e934b6ac9b76750df/treeee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9.

Four large originals use deterministic gzip plus ordered base64 chunks. MANIFEST.json gives each original byte count, SHA-256 and Git-blob identity and every physical member identity. Run `python verify.py` for pure data verification or `python verify.py --reconstruct <new-directory>` for exact reconstruction. The verifier imports only the Python standard library and executes no retained source, tests, preflight or workload.

The full original type output is preserved: zero errors and 30,181 warnings are not a warning-free result. The nested staging field pr_source_published:false is retained verbatim inside the later publication receipt; the top-level publication identity/timestamp records the actual later publication. Original local paths and all stderr streams, including empty streams, are unchanged.
