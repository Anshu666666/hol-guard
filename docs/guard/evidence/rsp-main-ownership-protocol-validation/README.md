# Main ownership-resolver protocol correction

`FunctionRecord` is frozen, while the resolver protocol previously declared
writable `path`, `qualname` and `node` attributes. The focused type check reproduced
that mismatch at `scoped_nodes`: one error and 16 warnings. Making the protocol
members read-only properties permits the existing frozen record without changing
its behavior or the resolver algorithm.

The final focused three-script type check exits 0 with **zero errors and 16
unchanged warnings**. Ruff and formatting pass for the changed resolver. This is
not a zero-warning result. No behavior tests were repeated because the complete
module AST is unchanged outside the typing protocol declaration, as recorded in
[the equivalence receipt](raw/annotation-equivalence.json).

[manifest.json](manifest.json) binds the source hashes and every retained raw
file, including [the failed initial type check](raw/before-types.log),
[the corrected type check](raw/types.log), [commands and elapsed times](raw/manifest.json)
and [the exact patch](raw/protocol-readonly.patch). Patch context-space prefixes
are retained with a narrowly scoped whitespace attribute; the source patch bytes
are unchanged. All checks use the common measurement lock independently. No
product source, security disposition, build, benchmark or runtime activation is
part of this correction.
