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
  ../../../constantine/constantine/platforms/primitives,
  ../../../constantine/constantine/math/io/[io_fields],
  ../[math, upstream],
  ../err/verkle_error,
  ../tree/[tree, operations],
  ../../../constantine/constantine/serialization/[codecs]

proc loadStateDiff* (res: var StateDiff, inp: StateDiff)=
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
  pEl.CommByPath = initTable[string, EC_P]()

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
  pEl.CommByPath = initTable[string, EC_P]()

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

proc makeVKTMultiproof* (preroot, postroot: var BranchesNode, keys: var KeyList): (VerkleProofUtils, seq[EC_P], seq[Fr[Banderwagon]], seq[int], bool)=

  var pEl: ProofElements
  pEl.Cis = @[]
  pEl.Zis = @[]
  pEl.Fis = @[]
  pEl.Vals = @[]
  pEl.CommByPath = initTable[string, EC_P]()

  var es: seq[byte]
  var poass: seq[seq[byte]]
  var check = false
  var postvals = newSeq[seq[byte]](keys.len)
  
  (pEl, es, poass, postvals, check) = getProofElementsFromTree(preroot, postroot, keys)

  var config {.noInit.}: IPASettings
  discard config.genIPAConfig()

  var tr {.noInit.}: sha256
  tr.newTranscriptGen(asBytes"vt")

  var cis {.noInit.}: seq[EC_P]
  var fis: array[VerkleDomain, array[VerkleDomain, Fr[Banderwagon]]]

  for i in 0 ..< pEl.Cis.len:
    cis[i] = pEl.Cis[i]

  for i in 0 ..< VerkleDomain:
    for j in 0 ..< VerkleDomain:
      fis[i][j] = pEl.Fis[i][j]

  var mprv {.noInit.}: MultiProof
  var checks: bool
  checks = mprv.createMultiProof(tr, config, pEl.Cis, fis, pEl.Zis)

  var paths = newSeq[string](pEl.CommByPath.len - 1)
  for path, point in pEl.CommByPath:
    if path.len > 0:
      paths.add(path)

  paths.sort(hexComparator)
  var cis2 = newSeq[EC_P](pEl.CommByPath.len - 1)
  for i in 0 ..< paths.len:
    cis2[i] = pEl.CommByPath[paths[i]]

  var vktproofutils: VerkleProofUtils
  vktproofutils.Multipoint = mprv
  vktproofutils.Cs = cis2
  vktproofutils.ExtensionStatus = es
  vktproofutils.PoaStems = poass
  vktproofutils.Keys = keys
  vktproofutils.PreStateValues = pEl.Vals
  vktproofutils.PostStateValues = postvals

  return (vktproofutils, pEl.Cis, pEl.Yis, pEl.Zis, true)

proc verifyVerkleProof* (proof: var VerkleProofUtils, config: IPASettings, Cs: var openArray[EC_P], indices: var openArray[int], ys: var openArray[Fr[Banderwagon]]): bool =
  var tr {.noInit.}: sha256
  tr.newTranscriptGen(asBytes"vt")
  var checker = false
  checker = proof.Multipoint.verifyMultiproof(tr, config, Cs, ys, indices)

  return checker

proc verifyVerkleProofWithPreState* (config:IPASettings, proof: var VerkleProofUtils, preroot: var BranchesNode): bool =
  # verifyVerkleProofWithPreState takes a proof and a trusted tree root and verifies that the proof is valid
  var pElm: ProofElements
  var check = false
  var p0: seq[byte]
  var p1,p2: seq[seq[byte]]

  var post {.noInit.}: BranchesNode

  (pElm, p0, p1, p2, check) = getProofElementsFromTree(preroot, post, proof.Keys)

  discard p0
  discard p1
  discard p2

  var checker = false
  checker = verifyVerkleProof(proof, config, pElm.Cis, pElm.Zis, pElm.Yis)

  return checker
