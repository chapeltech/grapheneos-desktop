# Root picker diagnostic integration

Integrates the reviewed external candidate into the working-tree conformance
tool, not into any old sealed image or failed runtime receipt.

- Candidate receipt: `9b24fb7c5b75585a7461d8f29a605fdb9947cd78bcfd6e3655b7578b91eec194`.
- Tool preimage: `d193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5`.
- Expected tool postimage: `2dc0cfd88ee19adbf7c61d508b7c2a23b2c53d06e6ff4873ec8e829d27c43aae`.
- Root external replay: 20 tests passed, actual terminal chunk `96bb81`.
  It includes the 13 existing functional controls; neither is Android runtime
  evidence. The stray relative preimage hash command in that replay used the
  evidence cwd and failed; the absolute working-tree check was subsequently
  performed in chunk `c177ae` and returned the exact expected preimage.

The new in-repository regression suite is adapted to load the live tool and
bind unchanged authority helpers to their independently captured AST digests,
instead of comparing the installed tool with itself. All external proposal
files and old failed runtime evidence remain unchanged. Fresh image-bound
runtime execution is required; past missing raw observations are not repaired.
