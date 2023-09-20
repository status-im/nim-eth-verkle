#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides methods to generate commitments for tree nodes

import
  std/[tables, sequtils],
  elvis,
  ./tree

{.push warning[DotLikeOps]: off.}


# Todo: Initialize to montgomery X=0, Y=1, Z=1
const IdentityPoint = Point()


# Todo: implement; this is a mock
proc BanderwagonMultiMapToScalarField(fields: var openArray[Field], points: openArray[Point]) =
  for i in 0..<points.len:
    fields[i] = points[i].X


# Todo: implement; this is a mock
proc BanderwagonAddPoint(dst: var Point, src: Point) =
  dst.X[0] += src.X[0]


# Todo: implement; this is a mock
proc BandesnatchSubtract(x, y: Field): Field =
  [x[0] - y[0], 0, 0, 0]


# Todo: implement; this is a mock
proc IpaCommitToPoly(poly: array[256, Field]): Point =
  var x,y,z: Field
  for field in poly:
    x[0] += field[0]
  Point(X:x, Y:y, Z:z)


# Todo: implement
proc initializeCommitment*(vn: ValuesNode) =
  discard


# Todo: implement; this is a mock; we set the commitment's X[0] (uint64) to be
# the sum of the last byte of all stored values.
proc updateCommitment*(vn: ValuesNode, index: byte, newValue: ref Bytes32) =
  if vn.values[index] != nil:
    vn.commitment.X[0] -= vn.values[index][^1]
  if newValue != nil:
    vn.commitment.X[0] += newValue[^1]


proc snapshotChildCommitment*(node: BranchesNode, childIndex: byte) =
  ## Stores the current commitment of the child node denoted by `childIndex`
  ## into the `node`'s `commitmentsSnapshot` table, and allocates the table if
  ## needed. In case the child is nil, the empty Identity commitment is stored.
  ## This is done so that we can later compute the delta between the child's
  ## current commitment and updated commitment. That delta will be used to
  ## update the parent `node`'s own commitment.
  if node.commitmentsSnapshot == nil:
    node.commitmentsSnapshot = new Table[byte, Point]
  let childCommitment = node.branches[childIndex].?commitment ?: IdentityPoint
  discard node.commitmentsSnapshot.hasKeyOrPut(childIndex, childCommitment)


proc updateAllCommitments*(tree: BranchesNode) =
  ## Updates the commitments of all modified nodes in the tree, bottom-up.

  if tree.commitmentsSnapshot == nil:
    return

  var levels: array[31, seq[BranchesNode]]
  levels[0].add(tree)
  for node, depth, _ in tree.enumerateModifiedTree():
    if node of BranchesNode and node.BranchesNode.commitmentsSnapshot != nil:
      levels[depth].add(node.BranchesNode)

  for depth in countdown(30, 0):
    let nodes = levels[depth]
    if nodes.len == 0:
      continue

    var points: seq[Point]
    var childIndexes: seq[byte]

    for node in nodes:
      for index, commitment in node.commitmentsSnapshot:
        points.add(commitment)
        points.add(node.branches[index].commitment)
        childIndexes.add(index)
    
    var frs = newSeq[Field](points.len)
    BanderwagonMultiMapToScalarField(frs, points)

    var deltas = newSeq[Field]()
    for pair in frs.distribute(int(frs.len / 2)):
      deltas.add(BandesnatchSubtract(pair[1], pair[0]))

    var deltasIdx, childIndexesIdx = 0
    for node in nodes:
      var poly: array[256, Field]
      for _ in 0 ..< node.commitmentsSnapshot.len:
        poly[childIndexes[childIndexesIdx]] = deltas[deltasIdx]
        inc(childIndexesIdx)
        inc(deltasIdx)
      node.commitmentsSnapshot = nil
      node.commitment.BanderwagonAddPoint(IpaCommitToPoly(poly))


#[

There are several possible approaches on how to track mutations to the trie and
update commitments. They have tradeoffs in performance, RAM usage and software
complexity.

One approach, used in the Geth client, is to have tree nodes store a mapping
between the index of a child node and its commitment before modifications. This
allows traversing the modified portion of the tree by starting from the root
node and going down any node that has a non-empty mapping. Let's call this the
"in-tree" approach.

To update commitments, 31 lists are allocated (the maximum depth of the tree
minus one), the modified nodes are traversed, and appended to the list matching
their depth. Then, all modified nodes at the lowest layer of the tree have their
commitments updated, using bulk operations where possible. Then, the layer above
is updated, and uses the cached commitments of its modified children to compute
the delta between their previous and current commitments, and update their own
comitments accordingly. This process goes on up the tree layers till the root is
reached. The mappings with old commitment values are cleared along the way.

A similar approach could be to store the modified node commitments outside of
the tree in a separate tree. A kind of copy-on-write snapshot.

Another possible approach is to have a list of modifications done to the tree.
Each entry could hold a reference to the respective node. The list can be stored
separately from the tree. To update commitments, we could sort the list
according to the depth at which a modification was made (deepest first), then
take ranges in the list (per depth) and bulk-update commitments, while storing
the original commitments aside for the next iteration. Let's call this the
"modifications list" approach. It has some advantages and disadvantages.

We chose to use the "in-tree" approach. However, it's worth reevaluating this
later on when the implementation matures a bit. Here's a brain dump of the pros
and cons.


Approach:                                         In-tree                     Mods list
  
Performance:             
  Ram increase for unmodified tree                map ptr                     parent ptr, depth, index
  Ram increase for modified tree                  map per node; fragmented.   low; entry in list
                                                  commitment per node
  Change tracking performance                     map nil test, allocation,   add entry to list
                                                    lookup, copy commitment   
  Commitments update performance                  Alloc 32 arrays & layout    sort list; O(n*log(n))
                                                    nodes by depth; O(n)      populate temp list per depth
  Commitments update pipeline                     Leaves: immediately         Leaves: later
                                                  Branches: later             Branches: later

Change management:                                      
  Tracking multiple updates at same location      No                          Yes
  Merging  multiple updates at same location      Yes; map lookup             No; need to de-dup
  Undo changes to tree in case of chain reorg     Impossible                  Run changes list in reverse
  Untracking non-change (set same value)          Hard                        Easy; not appending to the list
  Serialization & logging                         Only final state;           All changes; stand-alone
                                                    tied to tree
  
Maintenance:
  Implementation complexity                       Low                         High
  Separation of tree operations vs commitments    Medium                      Good
  
Future:
  Flexibility in bulk operations                  Good; all modified          Medium; handling one depth
      (incl. database writes)                       state is in arrays          layer at a time
  Flexibility for future optimizations            Good; instant access        Medium; handling one depth
                                                    to all modified state       layer at a time
  Parent-child relationship during comms update   Weak                        Strong

]#
