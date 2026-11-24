# Vendored GEM optimal-transport solver

`core.h`, `full_bipartitegraph.h`, `network_simplex_simple.h`, `EMD.h`, and
`EMD_wrapper.cpp` are hard copies from `ref_repo/sigmod26gem` commit
`1b559d0ccb2bea7a23ac9f2f8e84040924e3972f`, directory `hnswlib/otlib/`.

`gem_emd_shim.cpp` is a local narrow C ABI around the same
`NetworkSimplexSimple` instantiation. The default `lemon-qemd` feature uses
this hard copy through the checked
`gem-qemd-lemon` adapter. The Rust transport solver remains available through
`--no-default-features` as a slow parity oracle; selecting either implementation
must not change exact distance bits or the serialized graph.
