# Frozen upstream differential reference

The upstream GEM checkout was VectorDB-NTU/GEM at commit `1b559d0ccb2bea7a23ac9f2f8e84040924e3972f`.
The JSON next to this file is the recorded output. The Rust differential tests load it at compile time.
The historical harness and patch are retained to identify how the reference was produced.
Use the workspace tests to check the frozen reference. A complete upstream C++ regeneration toolchain is outside this package.
