#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  verkle_proof_utils,
  ipa_proof,
  execution_witness,
  algorithm,
  tables,
  sets,
  ../../../constantine/constantine/platforms/primitives,
  ../../../constantine/constantine/math/io/[io_fields],
  ../[math, upstream],
  ../err/verkle_error,
  ../tree/[tree, operations],
  ../../../constantine/constantine/serialization/[codecs, codecs_banderwagon]

proc constructPreStateTreeFromProof* (vkp: var VerkleProofUtils, rootComm: var EC_P): (BranchesNode, bool)=
  ## Constructing the Pre State tree, a stateless pre state tree from the VerkleProof
  doAssert vkp.Keys.len == vkp.PreStateValues.len, "Number of keys and the number of pre-state values should be EQUAL!"
  doAssert vkp.Keys.len == vkp.PostStateValues.len, "Number of Keys and the number of post-state values should be EQUAL!"

  var stems = newSeq[seq[byte]](vkp.Keys.len)

  for i in 0 ..< vkp.Keys.len:
    var stem = keyToStem(vkp.Keys[i])
    if stems.len == 0 or stems[stems.len - 1] != stem:
      stems[i].add(stem)

  doAssert stems.len == vkp.ExtensionStatus.len, "Invalid Number of stems and Execution Statuses!"

  var info: Table[string, StemInfo]
  var paths: seq[seq[byte]]
  var checker: bool
  var poas = vkp.PoaStems

  let stat = isStemSorted(vkp.PoaStems)
  doAssert stat == false, "Proof of Absence stems must be sorted!"

  var pathsWithExtensionPresent: HashSet[string] = initHashSet[string]()
  var idx = 0
  for ext in vkp.ExtensionStatus:
    if ((ext and 3) == uint8(extStatusPresent)).bool() == true:
      var interim: seq[byte]
      interim = stems[idx][0..<(ext shr 3)]
      let interim_string: string = cast[string](interim)
      discard interim

      pathsWithExtensionPresent.incl(interim_string)
    ## Caching mechanism for the paths that have an extension present
    inc(idx)

