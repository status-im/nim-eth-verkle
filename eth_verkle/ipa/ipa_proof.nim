#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  verkle_proof_utils,
  algorithm,
  tables,
  ../[math, encoding],
  ../../../constantine/constantine/hashes,
  ../../../constantine/constantine/
  [
    ethereum_verkle_trees, 
    ethereum_verkle_primitives
  ],
  ../../../constantine/constantine/platforms/primitives,
  ../../../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../../../constantine/constantine/math/arithmetic,
  ../../../constantine/constantine/math/config/curves,
  ../../../constantine/constantine/math/io/[io_bigints, io_fields],
  ../[encoding, math],
  ../err/verkle_error,
  ../tree/[tree, operations],
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
  Cs*: seq[Point]
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

proc getCommitmentsForMultiproof* (root: var BranchesNode, keys: var KeyList): (ProofElements, seq[byte], seq[seq[byte]], bool)=
  keys.sort(comparatorFor2DimArrays)

  var pEl: ProofElements
  pEl.Cis = @[]
  pEl.Zis = @[]
  pEl.Fis = @[]
  pEl.Vals = @[]
  pEl.CommByPath = initTable[string, Point]()

  var outs: seq[byte]
  var outStem: seq[seq[byte]]
  var check = false
  (pEl, outs, outStem, check) = getProofItems(root, keys)

  return (pEl, outs, outStem, true)

proc getProofElementsFromTree* (preroot, postroot: var BranchesNode, keys: var KeyList): (ProofElements, seq[byte], seq[seq[byte]], seq[seq[byte]], bool)=
  ## this function leverages the logic that is used both in the proving and verifying methods.
  ## it takes a pre-state tree and an optional post-state tree, extracts the proof data from them and returns
  ## all the items required to build/verify a proof.
  var pEl: ProofElements
  pEl.Cis = @[]
  pEl.Zis = @[]
  pEl.Fis = @[]
  pEl.Vals = @[]
  pEl.CommByPath = initTable[string, Point]()

  if keys.len == 0:
    return (pEl, @[], @[@[]], @[@[]], false)

  var es: seq[byte]
  var poass: seq[seq[byte]]
  var check = false

  (pEl, es, poass, check) = getCommitmentsForMultiproof(preroot, keys)
  if check == false:
    return (pEl, @[], @[@[]], @[@[]], false)

  var postvals = newSeq[seq[byte]](keys.len)
  postvals = @[@[]]
  if postroot.isNil() == false:
    ## Keys were sorted already in getCommitmentsForMultiproof
    ## Set the post values, if they are untouched leaving them nil
    for i in 0..<keys.len:
      var val: ref Bytes32
      val = postroot.getValueSeq(keys[i])

      for j in 0 ..< 32:

        if pEl.Vals[i][j] == val[j]:
          postvals[i][j] = val[j]

  ## [0..3]: Proof elements of the pre-state trie for serialization
  ## 3: values to be inserted in the post-state trie for serialization
  return (pEl, es, poass, postvals, true)

proc makeVKTMultiproof* (preroot, postroot: var BranchesNode, keys: var KeyList): (VerkleProofUtils, seq[Point], seq[Field], seq[byte], bool)=

  var pEl: ProofElements
  pEl.Cis = @[]
  pEl.Zis = @[]
  pEl.Fis = @[]
  pEl.Vals = @[]
  pEl.CommByPath = initTable[string, Point]()

  var es: seq[byte]
  var poass: seq[seq[byte]]
  var check = false
  var postvals = newSeq[seq[byte]](keys.len)
  
  (pEl, es, poass, postvals, check) = getProofElementsFromTree(preroot, postroot, keys)

  var config {.noInit.}: IPASettings
  discard config.genIPAConfig()

  var tr {.noInit.}: sha256
  tr.newTranscriptGen(asBytes"vt")

  var mprv {.noInit.}: MultiProof
  var checks = false
  var cis {.noInit.}: seq[EC_P]
  var fis {.noInit.}: array[VerkleDomain, array[VerkleDomain, Fr[Banderwagon]]]
  checks = mprv.createMultiProof




