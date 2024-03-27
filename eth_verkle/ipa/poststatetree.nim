#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ".."/math,
  ".."/tree/[tree, operations, commitment]

proc postStateTreeFromStateDiff* (preroot: var BranchesNode, stateDiff: var StateDiff): (BranchesNode, bool) =
  ## PostStateTreeFromProof uses the pre-state trie and the list of updated values
  ## to produce the stateless post-state trie
  var postroot {.noInit.}: BranchesNode
  postroot = preroot

  for i in 0 ..< stateDiff.len:
    var values: seq[seq[byte]]
    var doesOverwrite = true

    ## suffixDiff.NewValue.len > 0 --> this works only for a slice
    ## if this value is non-nil, it means the function for value insertion
    ## at the stem should be called, otherwise, updating the tree can be skipped
    
    for j in 0 ..< stateDiff[i].SuffixDiffsInVKT.len:
      if stateDiff[i].SuffixDiffsInVKT[j].NewVal.len != 0:
        doesOverwrite = true
        values[int(stateDiff[i].SuffixDiffsInVKT[j].Suffix)].add(stateDiff[i].SuffixDiffsInVKT[j].NewVal)

    if doesOverwrite:
      var stem: Bytes32
      for k in 0 ..< StemSize:
        stem[k] = stateDiff[i].Stem[k]

      ## Add stateless insertion of stem values
      for k in 0 ..< 32:
        var value: Bytes32
        for ki in 0 ..< value.len:
          value[ki] = values[k][ki]
        postroot.setValue(stem, value)
  
  postroot.updateAllCommitments()
  return (postroot, true)

    
