#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  verkle_proof_utils,
  ipa_proof,
  algorithm,
  tables,
  ../../../constantine/constantine/platforms/primitives,
  ../../../constantine/constantine/math/io/[io_fields],
  ../[math, upstream],
  ../err/verkle_error,
  ../tree/[tree, operations],
  ../../../constantine/constantine/serialization/[codecs]

proc serializeToExecutionWitness* (proof: var VerkleProofUtils): (VerkleProof, StateDiff, bool)=
  ## serializeToExecutionWitness converts from VerkelProofUtils to the standardized
  ## ExecutionWitness Format:
  ##  - StateDiff
  ##  - VerkleProof
  ## 
  ## Therefore this function is useful in constructing the StateDiff
  ## from ExtensionStatuses and CommitmentsByPath
  ## 
  ## The serialization format is similar to Rust-Verkle:
  ## * len(Proof of absence stem) || Proof of absence stems
  ## * len(depths) || serialize(depth || extension status [i])
  ## * len(commitments || serialize(commitments)
  ## * Multipoint proof
  ## 
  var otherStems = newSeq[Stem](proof.PoaStems.len)

  for i in 0 ..< proof.PoaStems.len:
    for j in 0 ..< StemSize:
      otherStems[i][j] = proof.PoaStems[i][j]

  var cbp = newSeq[Bytes32](proof.Cs.len)
  for i in 0 ..< proof.Cs.len:
    var serializedCs: array[32, byte]
    serializedCs = serializePoint(proof.Cs[i])
    for j in 0 ..< 32:
      cbp[i][j] = serializedCs[j]

  var stemDiff {.noInit.}: StemStateDiff
  var stateDiff: StateDiff

  for i in 0 ..< proof.Keys.len:
    var stem = keyToStem(proof.Keys[i])
    if stemDiff.Stem != stem:
      var stemDiffInter {.noInit.}: StemStateDiff
      stateDiff.add(stemDiffInter)

      stemDiff = stateDiff[stateDiff.len - 1]

      for j in 0 ..< stemDiff.Stem.len:
        stemDiff.Stem[j] = stem[j]

    var suffixStateDiffInter {.noInit.}: SuffixStateDiff
    suffixStateDiffInter.Suffix = proof.Keys[i][StemSize]

    stemDiff.SuffixDiffsInVKT.add(suffixStateDiffInter)
    var newsd: SuffixStateDiff
    newsd = stemDiff.SuffixDiffsInVKT[stemDiff.SuffixDiffsInVKT.len - 1]

    var valueLen = proof.PreStateValues[i].len

    case valueLen
    of 0:
      discard
    of 32:
      for k in 0 ..< newsd.CurrentVal.len:
        newsd.CurrentVal[k] = proof.PreStateValues[i][k]
    else:
      var alignedBytes: array[32, byte]
      for k in 0 ..< valueLen:
        alignedBytes[k] = proof.PreStateValues[i][k]
      for k in 0 ..< newsd.CurrentVal.len:
        newsd.CurrentVal[k] = alignedBytes[k]
      
    valueLen = proof.PostStateValues[i].len

    case valueLen
    of 0:
      discard
    of 32:
      for k in 0 ..< newsd.NewVal.len:
        newsd.NewVal[k] = proof.PostStateValues[i][k]
    else:
      var alignedBytes: array[32, byte]
      for k in 0 ..< valueLen:
        alignedBytes[k] = proof.PostStateValues[i][k]
      for k in 0 ..< newsd.NewVal.len:
        newsd.NewVal[k] = alignedBytes[k]

  
  var D_bytes {.noInit.}: array[32, byte]
  var A_bytes {.noInit.}: array[32, byte]
  var cl_bytes {.noInit.}: array[8, array[32, byte]]
  var cr_bytes {.noInit.}: array[8, array[32, byte]]

  var serializedVerkleMultiproof {.noInit.}: VerkleMultiproofSerialized

  var checker = false
  checker = serializedVerkleMultiproof.serializeVerkleMultiproof(proof.Multipoint)

  var idx = 0
  for i in 0 ..< 576:
    D_bytes[idx] = serializedVerkleMultiproof[i]
    inc(idx)
  
  idx = 32
  for i in 0 ..< 8:
    for j in 0 ..< 32:
      cl_bytes[i][j] = serializedVerkleMultiproof[idx]
      inc(idx)

  idx = 288
  for i in 0 ..< 8:
    for j in 0 ..< 32:
      cr_bytes[i][j] = serializedVerkleMultiproof[idx]
      inc(idx)

  
  idx = 0
  for i in 544 ..< 576:
    A_bytes[idx] = serializedVerkleMultiproof[i]
    inc(idx)

  var ipaProofVKT {.noInit.}: IPAProofVkt
  ipaProofVKT.C_L = cl_bytes
  ipaProofVKT.C_R = cr_bytes
  ipaProofVKT.FinalEval = A_bytes

  var verkleProof {.noInit.}: VerkleProof
  verkleProof.CommitmentsByPath = cbp
  verkleProof.OtherStems = otherStems
  verkleProof.DepthExtensionPresent = proof.ExtensionStatus
  verkleProof.D = D_bytes
  verkleProof.IPAProofPView = ipaProofVKT

  return (verkleProof, stateDiff, true)
