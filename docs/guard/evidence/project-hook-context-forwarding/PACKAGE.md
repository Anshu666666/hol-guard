# Lossless publication packaging

The original README and `manifest.json` are preserved byte-for-byte from evidence
commit `e10e144cad2bf7bf28cb3f75f029358c3190cb87`. The historical manifest contains
36 records and describes the original materialization. Its `source.diff` record
now resolves through the explicit mapping in `package-manifest.json` to
`source.diff.gz`; decompression reproduces its original length and SHA-256.

The patch contains two legitimate unified-diff blank context lines, each encoded
as a space followed by a newline. Committing the raw patch as a newly added text
file caused the existing publication preparation whitespace check to fail. The
patch is now gzip-compressed losslessly, retaining every original context byte.
No source patch line, original manifest digest, assertion, test result, receiver
witness, or execution record has been edited.

`package-manifest.json` is the current self-contained publication index, with all
paths relative to this directory. It indexes the unchanged original README and
manifest, the compressed patch and all other retained files. Its historical
mapping verifies all 36 original records, including both stored/decoded metadata
for the original frozen-source gzip records. The original README's package-layout
paragraph describes the historical materialization; use this current package
index when validating the published files. This packaging correction grants no
new validation or qualification credit.
