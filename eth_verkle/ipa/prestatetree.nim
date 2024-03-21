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
  options,
  sets,
  ../../../constantine/constantine/platforms/primitives,
  ../../../constantine/constantine/math/io/[io_fields],
  ../[math, upstream],
  ../err/verkle_error,
  ../tree/[tree, operations],
  ../../../constantine/constantine/serialization/[codecs, codecs_banderwagon]



proc NewStatelessBranchesNode* (depth: uint8, comm: EC_P): BranchesNode =
  var bnode: BranchesNode
  bnode.depth = depth
  bnode.commitment = comm

  for i in 0 ..< bnode.branches.len:
    bnode.branches[i] = new BranchesNode

  return bnode



proc constructPartialViewPath* (n: var BranchesNode, path: var seq[byte], sInfo: var StemInfo, comms: var seq[EC_P], values: seq[seq[byte]]): (seq[EC_P], bool)=
  ## constructPartialViewPath inserts a given stem in the tree, placing it as described
  ## in the type StemInfo. It's third parameter is the list of the commitments that have
  ## not been assigned a node. 
  ## 
  ## It returns the same list, saves the commitments that were consumed during this call
  
  if path.len == 0:
    return (comms, false)

  ## If the path is 1 byte long, then the leaf node must be created
  if path.len == 1:
    case uint8(sInfo.stemType) and 3 

    of uint8(extStatusAbsentEmpty):
      ## Setting the branch to empty so that, in terms of Statelessness
      ## It is clear the node is EMPTY and UNKNOWN
      n.branches[path[0]] = nil

    of uint8(extStatusAbsentOther):
      if comms.len == 0:
        return (comms, false)

      if sInfo.stem.len != StemSize:
        return (comms, false)

      var newChild = new(ValuesNode)
      newChild.commitment = comms[0]

      var stemInter: array[31, byte]
      for i in 0 ..< stemInter.len:
        stemInter[i] = sInfo.stem[i]

      newChild.stem = stemInter
      discard stemInter

      for i in 0 ..< VerkleDomain:
        newChild.values[i] = nil
      
      newChild.depth = n.depth + 1
      newChild.poa = true

      n.branches[path[0]] = newChild
      
      var inter = comms[1..^1]
      comms = inter
      discard inter

    of uint8(extStatusPresent):
      if comms.len == 0:
        return (comms, false)

      if sInfo.stem.len != StemSize:
        return (comms, false)

      ## inserting the stem
      var newChild = new(ValuesNode)
      newChild.commitment = comms[0]

      var stemInter: array[31, byte]
      for i in 0 ..< stemInter.len:
        stemInter[i] = sInfo.stem[i]

      newChild.stem = stemInter
      discard stemInter

      var idx = 0
      for i in 0 ..< VerkleDomain:
        for j in 0 ..< 32:
          newChild.values[i][j] = values[idx][j]
        inc(idx)

      newChild.depth = n.depth + 1

      n.branches[path[0]] = newChild
      comms = comms[1..^1]

      if sInfo.stat_c1:
        if comms.len == 0:
          return (comms, false)
        newChild.c1 = comms[0]
        comms = comms[1..^1]

      else:
        newChild.c1 = IdentityPoint      

      if sInfo.stat_c2:
        if comms.len == 0:
          return (comms, false)
        newChild.c2 = comms[0]
        comms = comms[1..^1]

      else:
        newChild.c2 = IdentityPoint

      for key, value in pairs(sInfo.values):
        for j in 0 ..< 32:
          newChild.values[key][j] = value[j]
          
    else:
      return (comms, false)

    return (comms, true)

  if n.branches[path[0]] of BranchesNode:
    discard

  if n.branches[path[0]] of ValuesNode:
    return(comms, false)

  else:
    let newBranch = NewStatelessBranchesNode(n.depth + 1, comms[0])
    n.branches[path[0]] = newBranch
    discard newBranch

    comms = comms[1..^1]
  var pathNew = path[1..^1]

  constructPartialViewPath(n.branches[path[0]].BranchesNode, pathNew, sInfo, comms, values)



proc constructPreStateTreeFromProof* (vkp: var VerkleProofUtils, rootComm: var EC_P): (Option[BranchesNode], bool)=
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

  for i in 0 ..< vkp.ExtensionStatus.len:
    var sinfo: StemInfo
    sinfo.depth = uint8(vkp.ExtensionStatus[i]) shr 3
    sinfo.stemType = uint8(vkp.ExtensionStatus[i]) and 3

    var path: seq[byte]
    path = stems[i][0..<sinfo.depth]
    let pathStr:string = cast[string](path)
    case sinfo.stemType

    of uint8(extStatusAbsentEmpty):
      ## All the keys that are a part of a Proof Of Absence, must contain
      ## empty prestate values. If that isn't the case then we can conclude
      ## that the Verkle Proof is INVALID
      for j in 0 ..< vkp.Keys.len:
        var check1: bool
        check1 = hasStemPrefix(vkp.Keys[j], stems[i])

        doAssert check1 == true and vkp.PreStateValues[j].len != 0, "Proof of Absence (EMPTY) stem should NOT have any values in it!"
        discard check1

    of uint8(extStatusAbsentOther):
      ## All the keys that are part of a Proof of Absence, must contain empty
      ## prestate values. If that is not the case then the proof is INVALID
      for j in 0 ..< vkp.Keys.len:
        var check1: bool
        check1 = hasStemPrefix(vkp.Keys[j], stems[i])

        doAssert check1 == true and vkp.PreStateValues[j].len != 0, "Proof of Absence (OTHER) stem should NOT have any values in it!"
        discard check1

      if pathStr in pathsWithExtensionPresent:
        ## For this case of Proof of Absence in paths, we need to first check if this
        ## path contains a Proof of Presence. If that is the case, we don't really have 
        ## to do anything since the corresponding leaf will be constructed by that extension
        ## status itself.
        ## 
        ## Basically, we fetch the stem from the list of Proof of Absence stems
        continue

      if info.hasKey(pathStr):
        continue

      sinfo.stem = poas[0]
      poas = poas[1..<poas.len]
    
    of uint8(extStatusPresent):
      sinfo.values = initTable[byte, seq[byte]]()
      sinfo.stem = stems[i]

      for k in 0 ..< vkp.Keys.len:
        let k2s = keyToStem(vkp.Keys[k])
        if vkp.PreStateValues[k] == k2s:
          sinfo.values[vkp.Keys[k][StemSize]] = vkp.PreStateValues[k]
          sinfo.stat_c1 = sinfo.stat_c1 or (vkp.Keys[k][StemSize] < 128).bool()
          sinfo.stat_c2 = sinfo.stat_c2 or (vkp.Keys[k][StemSize] >= 128).bool()

    else:
      return (none(BranchesNode), false)

    info[pathStr] = sinfo
    paths[i].add(path)

  if poas.len != 0:
    return (none(BranchesNode), false)

  var root: BranchesNode
  root = NewStatelessBranchesNode(0, rootComm)
  var comms: seq[EC_P]
  comms = vkp.Cs

  for i in 0 ..< paths.len:
    var values: seq[seq[byte]]
    var pStr: string = cast[string](paths[i])

    for j in 0 ..< vkp.Keys.len:

      if vkp.PreStateValues[j].len == 0:
        continue

      let k2s = keyToStem(vkp.Keys[j])
      if k2s == info[pStr].stem:
        values[vkp.Keys[j][StemSize]] = vkp.PreStateValues[j]

    var path = paths[i]
    var check = false
    var stemInf = info[pStr]
    var updatedComms {.noInit.}: seq[EC_P]

    (updatedComms, check) = constructPartialViewPath(root, path, stemInf, comms, values)
    doAssert check == true, "Issue with constructing partial view path"

  return (some(root), true)
