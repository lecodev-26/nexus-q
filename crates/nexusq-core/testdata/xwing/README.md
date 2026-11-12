# X-Wing official test vectors

`draft-connolly-cfrg-xwing-kem-11.json` is a byte-for-byte copy of the test
vectors published with the X-Wing specification. Do not edit it; to move to a
newer draft, replace the whole file and update this note and the test in
`src/crypto/kem.rs`.

| | |
|---|---|
| Specification | [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11), Appendix C |
| Source | [`spec/test-vectors.json`](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json) at tag `draft-connolly-cfrg-xwing-kem-11` (commit `984c2f7`) |
| SHA-256 | `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` |

The file is unchanged since draft-05; every draft from 05 to 11 ships the same
vectors.

Each entry has `seed`, `sk`, `pk`, `eseed`, `ct` and `ss` as hex strings.
`sk` equals `seed`, the 32-byte X-Wing decapsulation key.
