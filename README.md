# Nimbus Verkle Tree implementation (WIP)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

[![Discord: Nimbus](https://img.shields.io/badge/discord-nimbus-orange.svg)](https://discord.gg/XRxWahP)
[![Status: #nimbus-general](https://img.shields.io/badge/status-nimbus--general-orange.svg)](https://get.status.im/chat/public/nimbus-general)

This repo will contain an implementation of [Verkle trees](https://dankradfeist.de/ethereum/2021/06/18/verkle-trie-for-eth1.html),
in the Nim programming language, to be integrated into the [Nimbus project](https://github.com/status-im/nimbus-eth1) when the implementation matures.

# TODO

## KZG polynomial commitments

- [ ] Evaluate if the [c-kzg-4844 library](https://github.com/ethereum/c-kzg-4844) can be used or extended to support computing KZG commitments with the parameters needed for Verkle trees (32 bytes keys and values, 256 items per commitment).
- [ ] If not, implement the logic by making use of [IPA Multipoint](https://github.com/crate-crypto/ipa_multipoint) / [Banderwagon](https://github.com/crate-crypto/banderwagon) / [blst](https://github.com/supranational/blst)
- [ ] Create tests focusing on the integration between the high-level Nim code and libraries, e.g. big/little endian issues


## Verkle tree implementation

- [ ] Implement the Verkle tree structure, with basic operations (e.g. adding nodes)
- [ ] Support computation of commitments / proofs. Possibly, cache them in the tree.
- [ ] Support tree mutation with minimal recomputation of commitments
- [ ] Create tests, focusing on edge cases (empty tree, sparse tree, dense tree, consistency after mutations). Possibly use fuzzing with deterministic random, as done in [rust-verkle](https://github.com/crate-crypto/rust-verkle/blob/master/verkle-trie/tests/trie_fuzzer.rs).
- [ ] Create comparative tests between the various Verkle implementations; given an identical tree, identical commitments are expected


## Performance

- [ ] Analyze how Nimbus accesses the Merkle tree
- [ ] Optimize the most common access patterns in the equivalent Verkle tree
- [ ] Evaluate whether parallelism can be leveraged
