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
    codecs, codecs_banderwagon, 
    codecs_status_codes
  ],
  ../math

#########################################################################
#
#                 Verkle Proof Items and it's Utilities
#
#########################################################################

type ProofElements* = object
  Cis*: var seq[EC_P]
  Zis*: var seq[byte]
  Yis*: var seq[Field]
  Fis*: var seq[seq[Field]]
  CommByPath*: var Table[string, EC_P]
  Vals*: seq[seq[byte]]
  cisZisTup*: var Table[EC_P, Table[uint8, bool]]

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
