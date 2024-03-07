#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the math primitives used to compute Verkle commitments,
##  obtained from the Constantine library

import
  tables,
  ../constantine/constantine/hashes,
  ../constantine/constantine/ethereum_verkle_trees,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves

type
  Bytes32* = Bytes

#########################################################################
#
#                 Verkle Proof Items and it's Utilities
#
#########################################################################

type KeyList* = seq[seq[byte]]

type ZisExistIT = Table[int, bool]
type CisZisTup =Table[EC_P, ZisExistIT]

type ProofElements* = object
  Cis*:                        seq[EC_P]
  Zis*:                        seq[int]
  Yis*:                        seq[Fr[Banderwagon]]
  Fis*:                        seq[seq[Fr[Banderwagon]]]
  Vals*:                       seq[seq[byte]]
  CommByPath*:                 Table[string, EC_P]
  cisZisTup*:                  CisZisTup

#########################################################################
#
#  Verkle Proof Types required to Interface Eth Verkle IPA in Constantine
#
#########################################################################

const IpaProofDepth*: int = 8

type IPAProofVkt* = object
  C_L: array[IpaProofDepth, array[32, byte]]
  C_R: array[IpaProofDepth, array[32, byte]]
  FinalEval: array[32, byte]

#########################################################
#
#  Helper types to rebuild the partial view of the tree
#
#########################################################

type VerkleProof* = object
  ## OtherStems stores the stems to which the leaf notes don't match initially in a Proof of Presence check.
  ## DepthExtensionPresent stores the depth to which the leaf is present
  ## Corresponding to a branch of the partial view
  ## CommitmentsByPath is a DFS-style walk of the Verkle Trie with each required commitment
  ## D + IPAProof is everything that the verifier needs to ensure that the partial view of
  ## The trie that is built is indeed correct.
  OtherStems*: seq[array[32, byte]]
  DepthExtensionPresent*: seq[byte]
  CommitmentsByPath*: seq[array[32, byte]]
  D*: array[32, byte]
  IPAProofPView*: IPAProofVkt 

type VerkleProofUtils* = object
  ## Multipoint argument
  ## ExtentionStatus for each stem
  ## Commitments sorted lexicographically by their path in the tree
  ## Stems proving the `to be proved` stem is absent
  Multipoint*: MultiProof
  ExtensionStatus*: seq[byte]
  Cs*: seq[EC_P]
  PoaStems*: seq[seq[byte]]
  Keys*: seq[seq[byte]]
  PreStateValues*: seq[seq[byte]]
  PostStateValues*: seq[seq[byte]]

type SuffixStateDiff* = object
  Suffix*: uint8
  CurrentVal*: var array[32, byte]
  NewVal*: array[32, byte]

type SuffixStateDiffs* = var seq[SuffixStateDiff]

const StemSize*: int = 31

type StemStateDiff* = object
  Stem*: seq[byte]
  SuffixDiffsInVKT*: SuffixStateDiffs

type StateDiff* = seq[StemStateDiff]

export
  ethereum_verkle_trees

export
  hashes,
  arithmetic,
  curves


