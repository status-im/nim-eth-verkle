#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import 
  tables,
  ../../../constantine/constantine/[
    ethereum_verkle_trees, 
    ethereum_verkle_primitives
  ],
  ../../../constantine/constantine/serialization/[
    codecs, 
    codecs_banderwagon, 
    codecs_status_codes
  ],
  ../math,
  ../tree/tree

#########################################################################
#
#                 Verkle Proof Items and it's Utilities
#
#########################################################################
type KeyList* = seq[seq[byte]]



type ProofElements* = object
  Cis*:                        seq[EC_P]
  Zis*:                        seq[byte]
  Yis*:                        seq[Field]
  Fis*:                        seq[seq[Field]]
  Vals*:                       seq[seq[byte]]
  CommByPath*:                 Table[string, EC_P]
  cisZisTup*:                  Table[EC_P, Table[uint8, bool]]

#########################################################################
#
#                     Utilities to Merge Proof Items
#
#########################################################################

func mergeProofElements* (res: var ProofElements, other: var ProofElements)=
  if res.cisZisTup.len == 0:
    for i, ci in res.Cis:
      if not res.cisZisTup.hasKey(ci):
        res.cisZisTup[ci] = initTable[uint8, bool]()
      res.cisZisTup[ci][res.Zis[i]] = true

  for i, ci in other.Cis:
    
    if not res.cisZisTup.hasKey(ci):
      res.cisZisTup[ci] = initTable[byte, bool]()

    if res.cisZisTup[ci].hasKey(other.Zis[i]):
      continue

    res.cisZisTup[ci][other.Zis[i]] = true
    res.Cis.add(ci)
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
    
#########################################################################
#
#                     Getter function for Proof Utils
#
#########################################################################

proc getProofItems* (n: BranchesNode, keys: KeyList): (ProofElements, seq[byte], seq[seq[byte]])=

  var groups = groupKeys(keys, n.depth)

  var extStatuses: seq[byte]
  var poaStatuses: seq[byte]

  var pElem: ProofElements

  pElem.Cis = @[]
  pElem.Zis = @[]
  pElem.Fis = @[]
  pElem.Vals = @[]
  pElem.CommByPath = initTable[string, EC_P]()

