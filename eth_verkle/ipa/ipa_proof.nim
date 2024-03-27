#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/algorithm,
  std/tables,
  std/strutils,
  std/sequtils,
  ".."/[encoding, math],
  ".."/tree/[tree, operations],
  ".."/err/verkle_error,
  "../../../constantine/constantine/serialization"/codecs

#########################################################################
#
#                     Utilities to Sort Keylists
#
#########################################################################

proc hasStemPrefix* (mainSlice, prefix: seq[byte]): bool=
  if prefix.len > mainSlice.len:
    return false

  for i in 0 ..< prefix.len:
    if mainSlice[i] != prefix[i]:
      return false

  return true

proc isStemSorted* (bytes: var seq[seq[byte]]): bool=
  for row in bytes:
    for i in 0 ..< row.len - 1:
      if row[i] > row[i + 1]:
        return false

  for i in 0 ..< bytes.len - 1:
    if bytes[i][^1] > bytes[i + 1][0]:
      return false
  
  return true

proc comparatorFor2DimArrays*(a, b: seq[byte]): int=
  var sumA = 0
  var sumB = 0

  for item in a:
    sumA += int(item)

  for item in b:
    sumB += int(item) 

  if sumA < sumB:
    return -1
  elif sumA > sumB:
    return 1
  else:
    return 0

#########################################################################
#
#                     Hexadecimal Comparator Function
#
#########################################################################

proc hexComparator* (x,y: string): int=
  let xi = parseHexInt(x)
  let yi = parseHexInt(y)
  if xi < yi: return -1
  elif xi > yi: return 1
  else: return 0



#########################################################################
#
#                     Utilities to Group Keys
#
#########################################################################

proc offsetKey*(key: seq[byte], depth: byte): byte = 
  if int(depth) < key.len:
    return key[depth]
  else:
    return 0


proc groupKeys*(keys: KeyList, depth: uint8): seq[KeyList]=
  if keys.len == 0:
    return @[]

  if keys.len == 1:
    return @[keys]

  var groups: seq[KeyList] = @[]
  var firstKey = 0
  var lastKey = 1

  while lastKey < keys.len:
    let key = keys[lastKey]
    let keyIdx = offsetKey(key, depth)
    let prevIdx = offsetKey(keys[lastKey - 1], depth)

    if keyIdx != prevIdx:
      groups.add(keys[firstKey ..< lastKey])
      firstKey = lastKey

    inc(lastKey)

  groups.add(keys[firstKey ..< lastKey])
  return groups

proc keyToStem* (key: openArray[byte]): seq[byte]=
  if key.len < 31:
    return @[]
  
  return key[0..31]

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

#########################################################################
#
#                     Utilities to Merge Proof Items
#
#########################################################################

proc mergeProofElements* (res: var ProofElements, other: var ProofElements)=
  if res.cisZisTup.len == 0:
    for i in 0 ..< res.Cis.len:
      var resCis: Bytes32
      resCis = res.Cis[i].serializePoint()
      if res.cisZisTup.hasKey(resCis) != true:
        res.cisZisTup[resCis] = initTable[int, bool]()
      res.cisZisTup[resCis][res.Zis[i]] = true

  for i in 0 ..< other.Cis.len:
    var otherCis: Bytes32
    otherCis = other.Cis[i].serializePoint()
    if res.cisZisTup.hasKey(otherCis) != false:
      res.cisZisTup[otherCis] = initTable[int, bool]()

    if res.cisZisTup[otherCis].hasKey(other.Zis[i]):
      continue

    res.cisZisTup[otherCis][other.Zis[i]] = true
    res.Cis.add(other.Cis[i])
    res.Zis.add(other.Zis[i])

    if res.Fis.len > 0:
      res.Fis.add(other.Fis[i])

    for path, c in other.CommByPath.pairs():
      if not res.CommByPath.hasKey(path):
        res.CommByPath[path] = c

    res.Vals.add(other.Vals)

  #########################################################################
#
#                     Getter function for Proof Utils
#
#########################################################################

proc getProofItems* (n: BranchesNode, keys: KeyList): (ProofElements, seq[byte], seq[seq[byte]], bool)=

  var groups = groupKeys(keys, n.depth)

  var extStatuses {.noInit.}: seq[byte]
  var poaStatuses: seq[seq[byte]]

  var pElem: ProofElements

  pElem.Cis = @[]
  pElem.Zis = @[]
  pElem.Fis = @[]
  pElem.Vals = @[]
  pElem.CommByPath = initTable[string, Point]()
  pElem.cisZisTup = initTable[Bytes32, Table[int, bool]]()

  var fi: array[VKTDomain, Field]
  var points: array[VKTDomain, Point]

  for i in 0 ..< n.branches.len:
    var child = n.branches[i]
    if child.isNil() == false:
      var c: Node
      if child of HashedNode:
        var childPath = newSeq[byte](n.depth + 1)
        childPath.add(keys[0][0..n.depth])
        childPath[n.depth] = uint8(i)
        var c = parseNode(childPath, n.depth + 1)
        n.branches[i] = c
      else:
        c = child
      points[i] = c.commitment
    else:
      points[i] = IdentityPoint

  fi.banderwagonMultiMapToScalarField(points)

  for i in 0 ..< groups.len:
    var childIdx = offsetKey(groups[0][i], n.depth)

    var yi: Field 
    yi = fi[childIdx]

    pElem.Cis.add(n.commitment)
    pElem.Zis.add(int(childIdx))
    pElem.Yis.add(yi)
    for i in 0 ..< pElem.Fis.len:
      pElem.Fis[i].add(fi)
    
    var inter: seq[byte]
    inter = groups[0][i][0..n.depth]
    var inter_hex = inter.toHex()
    pElem.CommByPath[inter_hex] = n.commitment

  for i in 0 ..< groups.len:
    var childIdx = offsetKey(groups[0][i], n.depth)

    #TODO: Cover cases for Unknown Nodes
    ## Special case of a proof of absence: no children
    ## commitment, or the value is at 0.
    if n.branches[childIdx].isNil() == true:
      var addedStems: Table[string, bool] = initTable[string, bool]()

      for j in 0 ..< groups[i].len:
        var stem: seq[byte] 
        stem = keyToStem(groups[i][j])
        var stemStr = stem.toHex()

        if addedStems[stemStr] == false:
          extStatuses.add(uint8(extStatusAbsentEmpty) or ((n.depth + 1) shl 3))
          addedStems[stemStr] = true

        var aux = fromHex(array[1, byte], "0x00")
        for k in 0 ..< pElem.Vals.len:
          pElem.Vals[i].add(aux)

      continue

    var pElemAdd: ProofElements
    pElemAdd.Cis = @[]
    pElemAdd.Zis = @[]
    pElemAdd.Fis = @[]
    pElemAdd.Vals = @[]
    pElemAdd.CommByPath = initTable[string, Point]()
    pElemAdd.cisZisTup = initTable[Bytes32, Table[int, bool]]()
    var extStatuses2: seq[byte]
    var other: seq[seq[byte]]
    var check = false

    (pElemAdd, extStatuses2, other, check) = getProofItems(n, groups[i])

    pElem.mergeProofElements(pElemAdd)
    poaStatuses.add(other)
    extStatuses.add(extStatuses2)

  return (pElem, extStatuses, poaStatuses, true)


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

proc makeVKTMultiproof* (preroot, postroot: var BranchesNode, keys: var KeyList): (VerkleProofUtils, seq[Point], seq[Field], seq[int], bool)=

  var pEl {.noInit.}: ProofElements
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

  var config {.noInit.}: IPAConf
  discard config.generateIPAConfiguration()

  var cis {.noInit.}: seq[Point]
  var fis: array[VKTDomain, array[VKTDomain, Field]]

  for i in 0 ..< pEl.Cis.len:
    cis[i] = pEl.Cis[i]

  for i in 0 ..< VKTDomain:
    for j in 0 ..< VKTDomain:
      fis[i][j] = pEl.Fis[i][j]

  var mprv {.noInit.}: Multipoint
  var checks: bool
  checks = mprv.createVKTMultiproof(config, pEl.Cis, fis, pEl.Zis)

  var paths = newSeq[string](pEl.CommByPath.len - 1)
  for path, point in pEl.CommByPath:
    if path.len > 0:
      paths.add(path)

  paths.sort(hexComparator)
  var cis2 = newSeq[Point](pEl.CommByPath.len - 1)
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

proc verifyVerkleProof* (proof: var VerkleProofUtils, config: IPAConf, Cs: var openArray[Point], indices: var openArray[int], ys: var openArray[Field]): bool =
  var checker = false
  checker = verifyVKTMultiproof(proof.Multipoint, config, Cs, ys, indices)

  return checker

proc verifyVerkleProofWithPreState* (config: IPAConf, proof: var VerkleProofUtils, preroot: var BranchesNode): bool =
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
