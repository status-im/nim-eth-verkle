#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import 
  tables,
  algorithm,
  sequtils,
  strutils,
  ../../../constantine/constantine/[
    ethereum_verkle_primitives
  ],
  ../../../constantine/constantine/serialization/[
    codecs, 
    codecs_banderwagon, 
    codecs_status_codes
  ],
  ../[encoding, math, upstream],
  ../err/verkle_error,
  ../tree/tree

#########################################################################
#
#                     Utilities to Sort Keylists
#
#########################################################################

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
#                     Utilities to Merge Proof Items
#
#########################################################################

func mergeProofElements* (res: var ProofElements, other: var ProofElements)=
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
  pElem.CommByPath = initTable[string, EC_P]()
  pElem.cisZisTup = initTable[Bytes32, Table[int, bool]]()

  var fi: array[VerkleDomain, Fr[Banderwagon]]
  var points: array[VerkleDomain, EC_P]

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

    var yi: Fr[Banderwagon] 
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
    pElemAdd.CommByPath = initTable[string, EC_P]()
    pElemAdd.cisZisTup = initTable[Bytes32, Table[int, bool]]()
    var extStatuses2: seq[byte]
    var other: seq[seq[byte]]
    var check = false

    (pElemAdd, extStatuses2, other, check) = getProofItems(n, groups[i])

    pElem.mergeProofElements(pElemAdd)
    poaStatuses.add(other)
    extStatuses.add(extStatuses2)

  return (pElem, extStatuses, poaStatuses, true)
