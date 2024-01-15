#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

#   Note: this code is heavily based on the Go Verkle implementation. See https://github.com/gballet/go-verkle

##  This module provides methods to generate commitments for tree nodes

import
  std/[tables, sequtils, strformat],
  elvis,
  ../utils,
  ./tree,
  ../../constantine/constantine/hashes,
  ../../constantine/constantine/serialization/[io_limbs, codecs],
  ../../constantine/constantine/platforms/primitives,
  ../../constantine/constantine/curves_primitives,
  ../../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../../constantine/constantine/math/arithmetic,
  ../../constantine/constantine/math/config/[type_ff, curves],
  ../../constantine/constantine/math/io/[io_bigints, io_fields, io_ec, io_extfields],
  ../../constantine/constantine/math/extension_fields,
  ../../constantine/constantine/ethereum_verkle_primitives,
  ../../constantine/constantine/ethereum_verkle_trees

{.push warning[DotLikeOps]: off.}

proc nestifyRepr(t: string): string =
  var depth = 0
  var i = 0
  while i < t.len:
    result.add t[i]
    if t[i] == '[':
      inc depth
    elif t[i] == ']':
      dec depth
    elif t[i] == '\n':
      for _ in 0 ..< depth:
        result.add "  "
    inc i

proc dbg[T](title: string, arg: T) =
  echo "\n", title, ": ", nestifyRepr repr arg

# Todo: can this be converted to a const?
var IdentityPoint: Point
IdentityPoint.x.setZero()
IdentityPoint.y.setOne()
IdentityPoint.z.setOne()

var ipaConfig: IPASettings
var ipaTranscript: IpaTranscript[sha256, 32]
discard ipaConfig.genIPAConfig(ipaTranscript)

var basisPoints : array[256, EC_P]
basisPoints.generate_random_points(ipaTranscript, 256)
dbg "basisPoints", basisPoints


proc ipaCommitToPoly(poly: array[256, Field]): Point =
  var comm: Point
  comm.pedersen_commit_varbasis(basisPoints, basisPoints.len, poly, poly.len)
  return comm


proc banderwagonMultiMapToScalarField(fields: var openArray[Field], points: openArray[Point]) =
  fields.batchMapToScalarField(points)


proc banderwagonMultiMapToScalarField2(fields: openArray[ptr Field], points: openArray[Point]) =
  var correctFields: seq[Fr[Banderwagon]] = @[]
  for field in fields:
    correctFields.add(Fr[Banderwagon](field[]))  # Assuming Fr[Banderwagon] can be initialized from a Field
  correctFields.batchMapToScalarField(points)


proc banderwagonAddPoint(dst: var Point, src: Point) =
  dst.sum(dst, src)


proc bandesnatchSubtract(x, y: Field): Field =
  result.diff(x, y)


# SetUint64 z = v, sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
proc bandesnatchSetUint64(z: var Field, v: uint64) =
  z.fromInt(int(v))


proc fromLEBytes(field: var Field, data: openArray[byte]) =
  var temp{.noinit.}: matchingOrderBigInt(Banderwagon)
  temp.unmarshal(data, littleEndian)
  field.fromBig(temp)


# leafToComms turns a leaf into two commitments of the suffix
# and extension tree.
proc leafToComms(field1, field2: var Field, val: Bytes32) =
  var valLoWithMarker: array[17, byte]
  var loEnd = 16
  if val.len < loEnd:
    loEnd = val.len
  valLoWithMarker[0..<loEnd] = val[0..<loEnd]
  valLoWithMarker[16] = 1 # 2**128
  fromLEBytes(field1, valLoWithMarker)
  if val.len >= 16:
    fromLEBytes(field2, val[16..^1])


# fillSuffixTreePoly takes one of the two suffix tree and
# builds the associated polynomial, to be used to compute
# the corresponding C{1,2} commitment.
proc fillSuffixTreePoly(poly: var openArray[Field], values: openArray[ref Bytes32]): int =
  result = 0
  for idx, val in values.pairs:
    if val != nil:
      inc result
      var i = (idx shl 1) and 0xFF
      leafToComms(poly[i], poly[i+1], val[])


let FrZero = Field()

const NodeWidth = 256
const CodeHashVectorPosition     = 3 # Defined by the spec.
const EmptyCodeHashFirstHalfIdx  = CodeHashVectorPosition * 2
const EmptyCodeHashSecondHalfIdx = EmptyCodeHashFirstHalfIdx + 1

proc makeEmptyHashCodePoly(): array[256, Field] =
  var heapValue = new Bytes32
  heapValue[0..31] = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".fromHex
  var values: array[256, ref Bytes32]
  values[CodeHashVectorPosition] = heapValue
  discard fillSuffixTreePoly(result, values[0..<128])

let EmptyCodeHashPoint = ipaCommitToPoly(makeEmptyHashCodePoly())
let EmptyCodeHashFirstHalfValue = makeEmptyHashCodePoly()[EmptyCodeHashFirstHalfIdx]
let EmptyCodeHashSecondHalfValue = makeEmptyHashCodePoly()[EmptyCodeHashSecondHalfIdx]

dbg "makeEmptyHashCodePoly", makeEmptyHashCodePoly()
dbg "EmptyCodeHashPoint", EmptyCodeHashPoint
dbg "EmptyCodeHashFirstHalfValue", EmptyCodeHashFirstHalfValue
dbg "EmptyCodeHashSecondHalfValue", EmptyCodeHashSecondHalfValue


proc initializeCommitment*(bn: BranchesNode) =
  bn.commitment = IdentityPoint


proc initializeCommitment*(vn: ValuesNode) =
  echo "\n\n\ninitializeCommitment() for ", cast[array[8, byte]](vn).toHex
  dbg "stem", vn.stem
  dbg "values", vn.values

  # C1.
  var c1poly: array[256, Field]
  var count = fillSuffixTreePoly(c1poly, vn.values[0..<128])
  let containsEmptyCodeHash =
    len(c1poly) >= EmptyCodeHashSecondHalfIdx and
    (c1poly[EmptyCodeHashFirstHalfIdx] == EmptyCodeHashFirstHalfValue).bool() and
    (c1poly[EmptyCodeHashSecondHalfIdx] == EmptyCodeHashSecondHalfValue).bool()

  dbg "c1poly", c1poly
  dbg "count", count
  dbg "containsEmptyCodeHash", containsEmptyCodeHash

  if containsEmptyCodeHash:
    # Clear out values of the cached point.
    c1poly[EmptyCodeHashFirstHalfIdx] = FrZero
    c1poly[EmptyCodeHashSecondHalfIdx] = FrZero
    # Calculate the remaining part of c1 and add to the base value.
    let partialc1 = ipaCommitToPoly(c1poly)
    dbg "partialc1", partialc1
    vn.c1 = EmptyCodeHashPoint
    vn.c1.banderwagonAddPoint(partialc1)
  else:
    vn.c1 = ipaCommitToPoly(c1poly)
  dbg "c1", vn.c1

  # C2.
  var c2poly: array[256, Field]
  count = fillSuffixTreePoly(c2poly, vn.values[128..<256])
  vn.c2 = ipaCommitToPoly(c2poly)
  dbg "c2poly", c2poly
  dbg "c2", vn.c2

  # Root commitment preparation for calculation.
  var poly: array[256, Field]
  poly[0].bandesnatchSetUint64(1)
  poly[1].fromLEBytes(vn.stem)
  banderwagonMultiMapToScalarField2([addr poly[2], addr poly[3]], [vn.c1, vn.c2])
  vn.commitment = ipaCommitToPoly(poly)

  dbg "poly", poly
  dbg "commitment", vn.commitment



proc updateCn(vn: ValuesNode, index: byte, value: ref Bytes32, c: var Point) =
  var
    old, newH: array[2, Field]
    diff:      Point
    poly:      array[NodeWidth, Field]

  # Optimization idea:
  # If the value is created (i.e. not overwritten), the leaf marker
  # is already present in the commitment. In order to save computations,
  # do not include it. The result should be the same,
  # but the computation time should be faster as one doesn't need to
  # compute 1 - 1 mod N.
  if vn.values[index] != nil:
    leafToComms(old[0], old[1], vn.values[index][])
  if value != nil:
    leafToComms(newH[0], newH[1], value[])

  newH[0] = newH[0].bandesnatchSubtract(old[0])
  poly[2*(index mod 128)] = newH[0]
  diff = ipaCommitToPoly(poly)
  poly[2*(index mod 128)] = FrZero
  c.banderwagonAddPoint(diff)

  newH[1] = newH[1].bandesnatchSubtract(old[1])
  poly[2*(index mod 128)+1] = newH[1]
  diff = ipaCommitToPoly(poly)
  c.banderwagonAddPoint(diff)



proc updateC(vn: ValuesNode, cxIndex: int, newC: Field, oldC: Field) =
  # Calculate the Fr-delta.
  let deltaC = newC.bandesnatchSubtract(oldC)

  # Calculate the Point-delta.
  var poly: array[NodeWidth, Field]
  poly[cxIndex] = deltaC

  # Add delta to the current commitment.
  let diff = ipaCommitToPoly(poly)
  vn.commitment.banderwagonAddPoint(diff)



proc updateCommitment*(vn: ValuesNode, index: byte, newValue: ref Bytes32) =
  if (vn.values[index] == nil and newValue == nil) or
     (vn.values[index] != nil and newValue != nil and vn.values[index][] == newValue[]):
    return

  var frs: array[2, Field]

  if index < NodeWidth div 2:
    var oldC1 = vn.c1
    vn.updateCn(index, newValue, vn.c1)
    # Batch the Fr transformation of the new and old CX.
    banderwagonMultiMapToScalarField2([addr frs[0], addr frs[1]], [vn.c1, oldC1])
  else:
    var oldC2 = vn.c2
    vn.updateCn(index, newValue, vn.c2)
    # Batch the Fr transformation of the new and old CX.
    banderwagonMultiMapToScalarField2([addr frs[0], addr frs[1]], [vn.c2, oldC2])

  # If index is in the first NodeWidth/2 elements, we need to update C1. Otherwise, C2.
  let cxIndex = 2 + int(index) div (NodeWidth div 2) # [1, stem, -> C1, C2 <-]
  vn.updateC(cxIndex, frs[0], frs[1])



proc snapshotChildCommitment*(node: BranchesNode, childIndex: byte) =
  ## Stores the current commitment of the child node denoted by `childIndex`
  ## into the `node`'s `commitmentsSnapshot` table, and allocates the table if
  ## needed. If the table already contains a previous value, it is not overriden.
  ## In case the child is nil, the empty Identity commitment is stored.
  ## This is done so that we can later compute the delta between the child's
  ## current commitment and updated commitment. That delta will be used to
  ## update the parent `node`'s own commitment.
  if node.commitmentsSnapshot.isNil:
    node.commitmentsSnapshot = new Table[byte, Point]
  let childCommitment = node.branches[childIndex].?commitment ?: IdentityPoint
  discard node.commitmentsSnapshot.hasKeyOrPut(childIndex, childCommitment)



proc updateAllCommitments*(tree: BranchesNode) =
  ## Updates the commitments of all modified nodes in the tree, bottom-up.

  if tree.commitmentsSnapshot.isNil:
    return

  var levels: array[31, seq[BranchesNode]]
  levels[0].add(tree)
  for node, depth, _ in tree.enumerateModifiedTree():
    if node of BranchesNode and (not node.BranchesNode.commitmentsSnapshot.isNil):
      levels[depth].add(node.BranchesNode)

  for depth in countdown(30, 0):
    let nodes = levels[depth]
    dbg "At level", depth
    if nodes.len == 0:
      continue

    var points: seq[Point]
    var childIndexes: seq[byte]

    for node in nodes:
      for index, commitment in node.commitmentsSnapshot:
        points.add(commitment)
        points.add(node.branches[index].commitment)
        childIndexes.add(index)

    dbg "Nodes", nodes
    dbg "Points", points
    dbg "childIndexes", childIndexes

    var frs = newSeq[Field](points.len)
    banderwagonMultiMapToScalarField(frs, points)

    var deltas = newSeq[Field]()
    for pair in frs.distribute(frs.len div 2):
      deltas.add(bandesnatchSubtract(pair[1], pair[0]))

    dbg "Deltas", deltas

    var deltasIdx, childIndexesIdx = 0
    for node in nodes:
      var poly: array[256, Field]
      for _ in 0 ..< node.commitmentsSnapshot.len:
        poly[childIndexes[childIndexesIdx]] = deltas[deltasIdx]
        inc(childIndexesIdx)
        inc(deltasIdx)
      node.commitmentsSnapshot = nil
      for index,field in poly:
        dbg &"poly[{index}]", field
      let diff = ipaCommitToPoly(poly)
      echo diff.toHex()
      echo &"\n\nUpdating node {cast[uint64](node.unsafeAddr)}'s commitment"
      dbg "Diff", diff
      dbg "Before", node.commitment
      node.commitment.banderwagonAddPoint(diff)
      dbg "After", node.commitment


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