#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ipa_proof,
  ../../../constantine/constantine/
  [
    ethereum_verkle_trees, 
    ethereum_verkle_primitives
  ],
  ../../../constantine/constantine/serialization/[codecs, codecs_banderwagon, codecs_status_codes]

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

func loadStateDiff* (res: var StateDiff, inp: StateDiff)=
  for i in 0 ..< inp.len:
    var auxStem {.noInit.}: seq[byte]
    auxStem.add(inp[i].Stem)
    res[i].Stem.add(auxStem)

    for j in 0 ..< inp[i].SuffixDiffsInVKT.len:
      var auxSuffix {.noInit.}: uint8
      auxSuffix = (inp[i].SuffixDiffsInVKT[j].Suffix)
      res[i].SuffixDiffsInVKT[j].Suffix = auxSuffix

      for k in 0 ..< 32:
        var aux = fromHex(array[1, byte], "0x00")
        if inp[i].SuffixDiffsInVKT[j].CurrentVal[k] != aux[0]:
          res[i].SuffixDiffsInVKT[j].CurrentVal[k] = aux[0]
          res[i].SuffixDiffsInVKT[j].CurrentVal[k] = inp[i].SuffixDiffsInVKT[j].CurrentVal[k]

      for k in 0 ..< 32:
        var aux = fromHex(array[1, byte], "0x00")
        if inp[i].SuffixDiffsInVKT[j].NewVal[k] != aux[0]:
          res[i].SuffixDiffsInVKT[j].NewVal[k] = aux[0]
          res[i].SuffixDiffsInVKT[j].NewVal[k] = inp[i].SuffixDiffsInVKT[j].NewVal[k]


    