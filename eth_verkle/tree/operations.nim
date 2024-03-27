#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides methods to get and modify the tree structure

import
  std/[sequtils, sugar],
  ".."/[utils, math, config],
  ./tree,
  ./commitment

when TraceLogs: import std/[strformat, strutils]


proc newValuesNode*(key, value: Bytes32, depth: uint8) : ValuesNode =
  ## Allocates a new `ValuesNode` with a single key and value and computes its
  ## commitment
  var heapValue = new Bytes32
  heapValue[] = value
  result = new ValuesNode
  result.depth = depth
  result.stem[0..<31] = key[0..<31]
  result.values[key[31]] = heapValue
  result.initializeCommitment()


proc newBranchesNode*(depth: uint8) : BranchesNode =
  ## Allocates a new `BranchesNode` with the given depth
  result = new BranchesNode
  result.depth = depth
  result.initializeCommitment()


proc newTree*() : BranchesNode =
  ## Inititalizes a new empty tree
  newBranchesNode(depth = 0)


proc setValue(node: ValuesNode, index: byte, value: Bytes32) =
  ## Heap-allocates the given `value` and stores it at the given `index`
  var heapValue = new Bytes32
  heapValue[] = value
  node.updateCommitment(index, heapValue)
  node.values[index] = heapValue


proc setValue*(node: BranchesNode, key: Bytes32, value: Bytes32) =
  assert node.depth == 0 # Must always be done from the tree root

  ## Stores the given `value` in the tree at the given `key`
  var current = node
  when TraceLogs: echo &"Setting {key.toHex} --> {value.toHex}"

  # Walk down the tree till the branch closest to the key
  while current.branches[key[current.depth]] of BranchesNode:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Going down to branch '{key[current.depth].toHex}' at depth {current.depth}"
    current.snapshotChildCommitment(key[current.depth])
    current = current.branches[key[current.depth]].BranchesNode

  # If we reached a ValuesNode...
  var vn = current.branches[key[current.depth]].ValuesNode
  if vn != nil:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Found ValuesNode at branch '{key[current.depth].toHex}', depth {current.depth}, addr {cast[uint64](vn)}"
    when TraceLogs: echo &"    Stem: {vn.stem.toHex}"

    # If the stem differs from the key, we can't use that ValuesNode. We need to
    # insert intermediate branches till the point they diverge, pushing down the
    # current ValuesNode, and then proceed to create a new ValuesNode
    # Todo: zip makes a memory allocation. avoid.
    var divergence = vn.stem.zip(key).firstMatchAt(tup => tup[0] != tup[1])
    if divergence.found:
      when TraceLogs: echo &"    Key:  {key.toHex}"
      when TraceLogs: echo &"    Found difference at depth {divergence.index}; inserting intermediate branches"
      while current.depth < divergence.index:
        let newBranch = newBranchesNode(current.depth + 1)
        current.snapshotChildCommitment(key[current.depth])
        current.branches[key[current.depth]] = newBranch
        when TraceLogs: echo &"At node {cast[uint64](current)}. Assigned new branch at '{key[current.depth].toHex}', depth {current.depth}, addr {cast[uint64](newBranch)}"
        current = newBranch
      current.snapshotChildCommitment(vn.stem[current.depth])
      current.branches[vn.stem[current.depth]] = vn
      vn.depth = current.depth + 1
      when TraceLogs: echo &"At node {cast[uint64](current)}. Assigned ValuesNode at '{vn.stem[current.depth].toHex}', depth {current.depth}, addr {cast[uint64](vn)}"
      vn = nil # We can't use it

  current.snapshotChildCommitment(key[current.depth])

  # The current branch does not contain a ValuesNode at the required offset;
  # create one and store the value in it, as per the key's last byte offset
  if vn == nil:
    vn = newValuesNode(key, value, current.depth + 1)
    current.branches[key[current.depth]] = vn
    when TraceLogs: echo &"Created ValuesNode at depth {current.depth}, branch '{key[current.depth].toHex}', stem {vn.stem.toHex}, with value at slot '{key[^1].toHex}'"

  # Store the value in the existing ValuesNode, as per the key's last byte offset
  else:
    vn.setValue(key[^1], value)
    when TraceLogs: echo &"Added value to slot '{key[^1].toHex}'"



proc getValue*(node: BranchesNode, key: Bytes32): ref Bytes32 =
  ## Retrieves a value given a key. Returns nil if not found.
  var current = node
  var depth = 0

  # Walk down the tree till the branch closest to the key
  while current.branches[key[depth]] of BranchesNode:
    current = current.branches[key[depth]].BranchesNode
    inc(depth)

  var vn = current.branches[key[depth]].ValuesNode
  if vn != nil and vn.stem == key[0..30] and vn.values[key[^1]] != nil:
    return vn.values[key[^1]]
  else: return nil


proc getValueSeq*(node: BranchesNode, key: seq[byte]): ref Bytes32 =
  ## Retrieves a value given a key. Returns nil if not found.
  var current = node
  var depth = 0

  # Walk down the tree till the branch closest to the key
  while current.branches[key[depth]] of BranchesNode:
    current = current.branches[key[depth]].BranchesNode
    inc(depth)

  var vn = current.branches[key[depth]].ValuesNode
  if vn != nil and vn.stem == key[0..30] and vn.values[key[^1]] != nil:
    var key_inter: uint8
    key_inter = key[^1]
    return vn.values[key_inter]
  else: return nil

proc deleteValueRecursive(node: BranchesNode, key: Bytes32):
    tuple[found: bool, empty: bool, values: ValuesNode] =
  ## Deletes the value associated with the given `key` from the tree, and prunes
  ## the tree as needed. Returns `found`=true in case the key was found and
  ## deleted. Returns `empty=true` in case the tree is now empty of data.
  ## May return a `ValuesNode` that has been orphanated and needs to be
  ## reattached to a higher up parent.

  #[
    Algorithm:
      - We walk down the tree and try to find the ValuesNodes that contains the
        value.
      - If we can't find it, or can't find the value within it, we return found=false
      - If we find it and the ValuesNodes contains more than one value, we set
        the target value to nil and update the ValuesNodes commitment.
        We return found=true, empty=false
      - If the ValuesNode contains just the target value, we simply detach it
        from its parent and discard it. We don't bother with removing the value
        or updating its commitment.
      - After detaching it, if the parent is left empty, we signal its own parent
        that it should be detached too, by returning empty=true
      - If the parent is left with one other ValuesNode (and no other BranchesNode),
        we signal its own parent that it should be detached, but that the other
        ValuesNode should be attached in its stead. We return it in the `values`
        tuple field.
      - When an ancestor obtains that ValuesNode, it will attach it in case it
        has at least one other brach (be it a ValuesNode or BranchesNode).
        Otherwise, it will notify its own parent it should be disconnected as
        well and pass the ValuesNode along.
      - Meaning, the ValuesNode (sibling to the ValuesNode from which the value
        was removed) starts travelling up the tree till it lands in a BranchesNode
        that contains one other branch, or reaches the root.
      - In any case of the tree being modified, we snapshot the commitments of
        nodes whose children were modified, so they can be bulk-updated later on.
        Leaves node commitments are updated on the spot though.
  ]# 

  var child = node.branches[key[node.depth]]
  when TraceLogs: echo "  ".repeat(node.depth) & &"At branch {cast[uint64](node)}, depth {node.depth}, child index {key[node.depth].toHex}"

  if child == nil:
    return (found: false, empty: false, values: nil)

  elif child of ValuesNode:
    var vn = child.ValuesNode
    if vn.stem != key[0..30]:
      return (found: false, empty: false, values: nil)
    var target = vn.values[key[^1]]
    when TraceLogs: echo "  ".repeat(vn.depth) & &"At ValuesNode {cast[uint64](vn)}, depth {vn.depth}"
    if target == nil:
      when TraceLogs: echo "  ".repeat(vn.depth) & &"Value not found at index {key[^1].toHex}"
      return (found: false, empty: false, values: nil)
    node.snapshotChildCommitment(key[node.depth])
    var hasOtherValues = vn.values.any(v => v != nil and v != target)
    if hasOtherValues:
      when TraceLogs: echo "  ".repeat(vn.depth) & &"ValuesNode has multiple values; removing value at index {key[^1].toHex}"
      vn.updateCommitment(key[^1], nil)
      vn.values[key[^1]] = nil
      return (found: true, empty: false, values: nil)
    when TraceLogs: echo "  ".repeat(vn.depth) & &"ValuesNode contains only the target value at index {key[^1].toHex}; detaching from tree"
    node.branches[key[node.depth]] = nil

  elif child of BranchesNode:
    var bn = child.BranchesNode
    var (found, empty, values) = deleteValueRecursive(bn, key)
    if not found:
      return (found, empty, values)
    node.snapshotChildCommitment(key[node.depth])
    if not empty:
      return (found, empty, values)
    if values == nil:
      when TraceLogs: echo "  ".repeat(node.depth) & &"At branch {cast[uint64](node)}, depth {node.depth}. Detached child from tree."
      node.branches[key[node.depth]] = nil
    else:
      when TraceLogs: echo "  ".repeat(depth) & &"At branch {cast[uint64](node)}, depth {depth}. Replaced child with inner ValuesNode."
      values.depth = node.depth + 1
      node.branches[key[node.depth]] = values # propagate ValuesNode up the tree

  if node.branches.all(b => b == nil):
    return (found: true, empty: true, values: nil)
  elif node.branches.any(b => b of BranchesNode) or
       node.branches.foldl(if b of ValuesNode: a+1 else: a, 0) >= 2:
    return (found: true, empty: false, values: nil)
  else:
    let vn = node.branches.filter(b => b != nil and b != child)[0].ValuesNode
    return (found: true, empty: true, values: vn)



proc deleteValue*(node: BranchesNode, key: Bytes32): bool =
  ## Deletes the value associated with the given `key` from the tree, and prunes
  ## the tree as needed. Returns `found`=true in case the key was found and
  ## deleted. 
  assert node.depth == 0 ## Must be called on tree root
  return deleteValueRecursive(node, key).found
