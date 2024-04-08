#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  typeinfo,
  std/algorithm,
  std/tables,
  std/strutils,
  std/sequtils,
  ".."/[math, encoding],
  ".."/tree/[tree, operations, commitment],
  ".."/err/verkle_error


#########################################################################
#
#                     Utilities to Sort Keylists
#
#########################################################################

proc hasStemPix* (mainSlice, pix: seq[byte]): bool=
  if pix.len > mainSlice.len:
    return false

  for i in 0 ..< pix.len:
    if mainSlice[i] != pix[i]:
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

proc hexComparator* (a,b: string): int=
  return cmp(a.toLowerAscii(), b.toLowerAscii())

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

proc offsetKey*(key: Bytes32, depth: byte): byte = 
  if int(depth) < key.len:
    return key[depth]
  else:
    return 0


proc groupKeys*(keys: KeyList, depth: uint8): seq[KeyList]=
  if keys.len == 0:
    return @[]

  if keys.len == 1:
    return @[keys]

  var groups: seq[KeyList]
  var firstKey = 0
  var lastKey = 0

  while lastkey < keys.len:
    let key = keys[lastKey]
    let keyIdx = offsetKey(key, depth)
    let prevIdx = if lastKey > 0: offsetKey(keys[lastKey - 1], depth) else: -1

    if lastKey > 0 and keyIdx != prevIdx:
      groups.add(keys[firstkey ..< lastkey])  # Use slice notation ..< for inclusive start, exclusive end
      firstkey = lastkey

    inc(lastkey)

  # If the last group extends to the end of keys, add it as well
  if firstkey < len(keys):
    groups.add(keys[firstkey ..< len(keys)])

  return groups

proc keyToStem* (key: openArray[byte]): seq[byte]=
  if key.len < 31:
    return @[]
  
  return key[0..<31]

proc equalPaths* (key1, key2: openArray[byte]): bool=
  var outcome = false
  if keyToStem(key1) == keyToStem(key2):
    return true
  return false

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
      discard res.cisZisTup[resCis].hasKeyOrPut(res.Zis[i], true)

  for i in 0 ..< other.Cis.len:
    var otherCis: Bytes32
    otherCis = other.Cis[i].serializePoint()
    if res.cisZisTup.hasKey(otherCis) != true:
      res.cisZisTup[otherCis] = initTable[int, bool]()

    if res.cisZisTup[otherCis].hasKey(other.Zis[i]):
      continue

    res.cisZisTup[otherCis][other.Zis[i]] = true
    res.Cis.add(other.Cis[i])
    res.Zis.add(other.Zis[i])

    debugEcho "Working 7.5.."
    if res.Fis.len > 0:
      for i in 0 ..< res.Fis.len:
        res.Fis[i] = other.Fis[i]

    for path, c in other.CommByPath.pairs():
      if not res.CommByPath.hasKey(path):
        res.CommByPath[path] = c

    for i in 0 ..< res.Vals.len:
      res.Vals[i] = other.Vals[i]

  #########################################################################
#
#                     Getter function for Proof Utils
#
#########################################################################

proc getProofItems* (n: var ValuesNode, keys: var KeyList): (ProofElements, seq[byte], seq[seq[byte]], bool)=

  var polynom = newSeq[Field](VKTDomain)
  
  var poaStatuses = newSeq[seq[byte]](256)
  for i in 0 ..< 31:
    poaStatuses[i] = newSeq[byte](31)

  var extStatuses: seq[byte]

  var pElem: ProofElements
  pElem.Cis.add(n.commitment)
  pElem.Cis.add(n.commitment)

  pElem.Zis.add(0)
  pElem.Zis.add(1)

  pElem.Yis.add(polynom[0])
  pElem.Yis.add(polynom[1])

  pElem.Fis.add(polynom)
  pElem.Fis.add(polynom)

  var zeroSeq: array[1, byte]
  zeroSeq[0] = uint8(0)

  pElem.Vals.add(zeroSeq.toSeq)

  pElem.CommByPath = initTable[string, Point]()

  polynom[0].bandesnatchSetUint64(uint64(1))
  doAssert polynom[1].stemFromLEBytes(n.stem) == true, "Issue with extracting stem!"

  var has_c1, has_c2: bool
  for i in 0 ..< keys.len:
    ## Note that there maybe keys that do NOT correspond to this leaf node
    ## We should ONLY analyze the inclusions of C1/C2 for keys corresponding 
    ## to this leaf node stem.
    var key = keys[i]
    if equalPaths(n.stem, key):
      has_c1 = has_c1 or (key[StemSize] < 128).bool()
      has_c2 = has_c2 or (key[StemSize] >= 128).bool()
      if has_c2:
        break
    
  ## If this tree is a full tree (not a stateless tree), we know we have C1 and C2 values.
  ## We need them independently irrespective of has_c1 or has_c2 since the prover needs to 
  ## Fis to create the multiproof from the tree.
  
  if n.poa == false:
    var fieldd: array[2, Field]
    fieldd[0] = polynom[2]
    fieldd[1] = polynom[3]

    var pointt: array[2, Point]
    pointt[0] = n.c1
    pointt[1] = n.c2

    var check = false
    check = fieldd.banderwagonMultiMapToScalarFieldWithDecision(pointt)
    if check == false:
      return (pElem, @[], @[@[]], false)

  elif has_c1 == true or has_c2 == true:
    return (pElem, @[], @[@[]], false)

  if has_c1:
    pElem.Cis.add(n.commitment)
    pElem.Zis.add(2)
    pElem.Yis.add(polynom[2]) 
    pElem.Fis.add(polynom)

  if has_c2:
    pElem.Cis.add(n.commitment)
    pElem.Zis.add(3)
    pElem.Yis.add(polynom[3])
    pElem.Fis.add(polynom)

  var addedStems: Table[string, bool]
  addedStems = initTable[string, bool]()

  var idx = 0 
  var idx2 = 0
  ## Now adding the C_n level elements
  for i in 0 ..< keys.len:
    var key = keys[i]
    var keyStr: string = cast[string](key[0..<n.depth])
    pElem.CommByPath[keyStr] = n.commitment

    ## Proof of absence: case of a differing stem
    if equalPaths(n.stem, key) == false:
      ## If this is the first extension status added for this path.
      ## add the proof of absence stem (only once). If later we find a 
      ## proof of presence, we will clear the list since the proof of presence
      ## will be enough to provide the stem
      if extStatuses.len == 0:
        poaStatuses.add(n.stem.toSeq)
        inc(idx)

      ## Add an extension status absent for this stem.
      ## Note that we keep a cache to adding the same stem twice or more
      ## if there are multiple keys with the same stem
      var stemStr: string = cast[string](keyToStem(key))
      if addedStems.hasKeyOrPut(stemStr, true):
        extStatuses.add(uint8(uint8(extStatusAbsentOther) or (n.depth shl 3)))
      
      pElem.Vals.add(@[])
      inc(idx2)
      continue

      
    ## As mentioned above, if a proof of absence stem was found, and 
    ## it now turns out the same stem is used as a proof of presence, we 
    ## clear the proof-of-absence list to avoid redundancy. Note that we don't
    ## delete the extension statuses since that is needed to figure out which is 
    ## the correct stem for this path
    if poaStatuses.len > 0:
      poaStatuses = @[@[]]

    var suffix = key[StemSize]
    var suffixPolynom = newSeq[Field](VKTDomain)
    var scomcheck: bool
    var scom: Point

    debugEcho "Working 7..."

    if suffix >= 128:
      discard fillSuffixTreePoly(suffixPolynom, n.values[128..^1])
      scom = n.c2
    else:
      discard fillSuffixTreePoly(suffixPolynom, n.values[0..<128])
      scom = n.c1

    var leaves: array[2, Field]
    debugEcho "Working 7.2..."
    if n.values[suffix] != nil:
      ## Proof of absence: case of a missing value.
      ## 
      ## Suffix tree is present as a child of the extension
      ## but does not contain the requested suffix. This can 
      ## only happen when the leaf has never been written to 
      ## since after deletion the value would be set to zero 
      ## but still contain the leaf marker 2^128.
      leaves[0] = suffixPolynom[2*suffix]
      leaves[1] = suffixPolynom[2*suffix + 1]

    
    else:
      leaves[0] = FrZero 
      leaves[1] = FrZero
    
    pElem.Cis.add(scom)
    pElem.Cis.add(scom)

    pElem.Zis.add(int(2*suffix))
    pElem.Zis.add(int(2*suffix+1))

    pElem.Yis.add(leaves[0])
    pElem.Yis.add(leaves[1])

    pElem.Fis.add(suffixPolynom)
    pElem.Fis.add(suffixPolynom)
    
    debugEcho "Working 7.3.."
    if n.values[StemSize] != nil:
      pElem.Vals.add(n.values[StemSize][].toSeq)

    else:
      pElem.Vals.add(@[])

    var stemStr: string = cast[string](keyToStem(key))

    debugEcho "Working 7.3.1.."
    if addedStems.hasKeyOrPut(stemStr, true) == false:
      extStatuses.add(uint8(uint8(extStatusPresent) or (n.depth shl 3)))

    debugEcho "Working 7.4.."
    let slotPath = $(key[0 ..< n.depth]) & $(char(2 + int(suffix) div 128))
    discard pElem.CommByPath.hasKeyOrPut(slotPath, scom)

  return (pElem, extStatuses, poaStatuses, true)

proc getProofItems* (n: var BranchesNode, keys: var KeyList): (ProofElements, seq[byte], seq[seq[byte]], bool)=

  var groups = groupKeys(keys, n.depth)
  debugEcho "Groups len"
  debugEcho groups.len
  debugEcho groups[0].len
  debugEcho groups[0][0].toHex()
  var poaStatuses = newSeq[seq[byte]](256)
  for i in 0 ..< 31:
    poaStatuses[i] = newSeq[byte](31)

  var extStatuses: seq[byte]

  var pElem: ProofElements

  pElem.Cis = @[]
  pElem.Zis = @[]
  pElem.Yis = @[]
  pElem.Fis = @[@[]]
  pElem.CommByPath = initTable[string, Point]()
  pElem.cisZisTup = initTable[Bytes32, Table[int, bool]]()

  var fi: array[VKTDomain, Field]
  var points: array[VKTDomain, Point]

  for i in 0 ..< n.branches.len:
    var child = n.branches[i]
    if child != nil:
      var c: Node
      # if child of HashedNode:
      #   var childPath = newSeq[byte](n.depth + 1)
      #   for i in 0 ..< int(n.depth):
      #     childpath[i] = keys[0][i]
      #   childPath[n.depth] = uint8(i)
      #   var c = parseNode(childPath, n.depth + 1)
      #   debugEcho "Check parse node"
      #   n.branches[i] = c
      # else:
      c = child
      points[i] = c.commitment
    else:
      points[i] = IdentityPoint

  debugEcho "Working 4"
  fi.banderwagonMultiMapToScalarField(points)
  debugEcho groups.len
  debugEcho groups[0].len
  debugEcho groups[0][0].len

  for i in 0 ..< groups.len:
    var group = groups[i]
    var childIdx = offsetKey(group[0], n.depth)

    var yi: Field 
    yi = fi[childIdx]

    pElem.Cis.add(n.commitment)
    pElem.Zis.add(int(childIdx))
    pElem.Yis.add(yi)
    pElem.Fis.add(fi.toSeq)
    
    debugEcho "Working 4.1"
    debugEcho n.depth
    discard pElem.CommByPath.hasKeyOrPut($(group[0][^1]), n.commitment)

    debugEcho "Working 4.2"
  for i in 0 ..< groups.len:
    var group = groups[i]
    var childIdx = offsetKey(group[0], n.depth)

    #TODO: Cover cases for Unknown Nodes
    ## Special case of a proof of absence: no children
    ## commitment, or the value is at 0.
    if n.branches[childIdx].commitment.banderwagonPointEqual(IdentityPoint):
      var addedStems: Table[string, bool] = initTable[string, bool]()

      for j in 0 ..< group.len:
        var stem: seq[byte] 
        stem = keyToStem(group[j])
        var stemStr = $(stem)

        if addedStems.hasKeyOrPut(stemStr, true) == false:
          extStatuses.add(uint8(extStatusAbsentEmpty) or ((n.depth + 1) shl 3))

        pElem.Vals.add(@[])

      continue

    var pElemAdd: ProofElements
    var other = newSeq[seq[byte]](256)
    for i in 0 ..< 31:
      other[i] = newSeq[byte](31)

    var extStatuses2 = newSeq[byte](1)
    var checks = false
    debugEcho "Working 5"
    # if n.branches[childIdx] of BranchesNode:
    #   # n.snapshotChildCommitment(childIdx)
    #   # n = n.branches[childIdx].BranchesNode
    if n.branches[childIdx] != nil:
      if n.branches[childIdx] of BranchesNode:
        debugEcho "Working 5.1"
        (pElemAdd, extStatuses2, other, checks) = n.branches[childIdx].BranchesNode.getProofItems(group)

      elif n.branches[childIdx] of ValuesNode:
        debugEcho "Working 5.2"
        # var vn = ((ValuesNode)n.branches[childIdx])
        (pElemAdd, extStatuses2, other, checks) = n.branches[childIdx].ValuesNode.getProofItems(group)

      pElem.mergeProofElements(pElemAdd)
      debugEcho "Working 5.5"
      poaStatuses.add(other)

      # # var finalpoa: array[256, Bytes32]
      # # for i in 0 ..< 256:
      # #   for j in 0 ..< 32:
      # #     finalpoa[i][j] = poaseq[i][j]

      extStatuses.add(extStatuses2)

  return (pElem, extStatuses, poaStatuses, true)


proc getCommitmentsForMultiproof* (root: var BranchesNode, keys: var KeyList, pEl: var ProofElements, outs: var seq[byte], outStem: var seq[seq[byte]]): bool=
  keys.sort(comparatorFor2DimArrays)

  var check = false
  debugEcho "Working 3"
  (pEl, outs, outStem, check) = root.getProofItems(keys)

  return check

proc getProofElementsFromTree* (preroot, postroot: var BranchesNode, keys: var KeyList, pEl: var ProofElements, es: var seq[byte], poass: var seq[seq[byte]], postvals: var seq[seq[byte]]): bool=
  ## this function leverages the logic that is used both in the proving and verifying methods.
  ## it takes a pre-state tree and an optional post-state tree, extracts the proof data from them and returns
  ## all the items required to build/verify a proof.
  debugEcho "Working <2"
  if keys.len == 0:
    return false

  debugEcho "Working 2"
  var check = false
  check = preroot.getCommitmentsForMultiproof(keys, pEl, es, poass)
  doAssert check == true, "Issue with get commitments for multiproof!"

  if postroot != nil:
    ## Keys were sorted already in getCommitmentsForMultiproof
    ## Set the post values, if they are untouched leaving them nil
    for i in 0..<keys.len:
      var val: ref Bytes32
      val = postroot.getValueSeq(keys[i])

      # for j in 0 ..< 32:
      #   if pEl.Vals[i][j] == val[j]:
      #     postvals[i][j] = val[j]

  ## [0..3]: Proof elements of the pre-state trie for serialization
  ## 3: values to be inserted in the post-state trie for serialization
  return true

proc makeVKTMultiproof* (preroot, postroot: var BranchesNode, keys: var KeyList): (VerkleProofUtils, seq[Point], seq[int], seq[Field], bool)=

  var es: seq[byte]
  var poass: seq[seq[byte]]
  var check: bool
  var postvals: seq[seq[byte]]
  var vktproofutils: VerkleProofUtils
  var pEl: ProofElements
  
  check = preroot.getProofElementsFromTree(postroot, keys, pEl, es, poass, postvals)

  var config {.noInit.}: IPAConf
  discard config.generateIPAConfiguration()

  # var cis {.noInit.}: seq[Point]

  # for i in 0 ..< pEl.Cis.len:
  #   cis[i] = pEl.Cis[i]

  var fis: array[VKTDomain, array[VKTDomain, Field]]

  for i in 0 ..< pEl.Fis.len:
    for j in 0 ..< pEl.Fis[i].len:
      fis[i][j] = pEl.Fis[i][j]

  var mprv {.noInit.}: Multipoint
  var checks: bool

  checks = mprv.createVKTMultiproof(config, pEl.Cis, fis, pEl.Zis)

  var paths = newSeq[string](pEl.CommByPath.len)
  for path, point in pEl.CommByPath:
    if path.len > 0:
      paths.add(path)


  paths.sort(hexComparator)
  var cis2 = newSeq[Point](pEl.CommByPath.len)
  for i in 0 ..< paths.len:
    if pEl.CommByPath.hasKey(paths[i]):
      cis2.add(pEl.CommByPath[paths[i]])

  vktproofutils.Multipoint = mprv
  vktproofutils.Cs = cis2
  vktproofutils.ExtensionStatus = es
  vktproofutils.PoaStems = poass
  vktproofutils.Keys = keys
  vktproofutils.PreStateValues = pEl.Vals
  vktproofutils.PostStateValues = postvals

  return (vktproofutils, pEl.Cis, pEl.Zis, pEl.Yis, true)

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

  check = getProofElementsFromTree(preroot, post, proof.Keys, pElm, p0, p1, p2)

  discard p0
  discard p1
  discard p2

  var checker = false
  checker = verifyVerkleProof(proof, config, pElm.Cis, pElm.Zis, pElm.Yis)

  return checker