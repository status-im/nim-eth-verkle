#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides methods to get and modify the tree structure

import
  std/[sequtils, sugar],
  ".."/[utils, config],
  ./tree,
  ./commitment

when TraceLogs: import std/strformat


proc newValuesNode(key, value: Bytes32) : ValuesNode =
  ## Allocates a new `ValuesNode` with a single key and value and computes its
  ## commitment
  var heapValue = new Bytes32
  heapValue[] = value
  result = new ValuesNode
  result.stem[0..<31] = key[0..<31]
  result.values[key[31]] = heapValue
  result.initializeCommitment()


proc setValue(node: ValuesNode, index: byte, value: Bytes32) =
  ## Heap-allocates the given `value` and stores it at the given `index`
  var heapValue = new Bytes32
  heapValue[] = value
  node.updateCommitment(index, heapValue)
  node.values[index] = heapValue


proc deleteValue(node: ValuesNode, index: byte) =
  ## Deletes the value at the given `index`, if any
  node.updateCommitment(index, nil)
  node.values[index] = nil


# TODO: prevent setting a value from a non-root node
proc setValue*(node: BranchesNode, key: Bytes32, value: Bytes32) =
  ## Stores the given `value` in the tree at the given `key`
  var current = node
  var depth = 0
  when TraceLogs: echo &"Setting {key.toHex} --> {value.toHex}"

  # Walk down the tree till the branch closest to the key
  while current.branches[key[depth]] of BranchesNode:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Going down to branch '{key[depth].toHex}' at depth {depth}"
    current.snapshotChildCommitment(key[depth])
    current = current.branches[key[depth]].BranchesNode
    inc(depth)

  # If we reached a ValuesNode...
  var vn = current.branches[key[depth]].ValuesNode
  if vn != nil:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Found ValuesNode at branch '{key[depth].toHex}', depth {depth}, addr {cast[uint64](vn)}"
    when TraceLogs: echo &"    Stem: {vn.stem.toHex}"

    # If the stem differs from the key, we can't use that ValuesNode. We need to
    # insert intermediate branches till the point they diverge, pushing down the
    # current ValuesNode, and then proceed to create a new ValuesNode
    # Todo: zip makes a memory allocation. avoid.
    var divergence = vn.stem.zip(key).firstMatchAt(tup => tup[0] != tup[1])
    if divergence.found:
      when TraceLogs: echo &"    Key:  {key.toHex}"
      when TraceLogs: echo &"    Found difference at depth {divergence.index}; inserting intermediate branches"
      while depth < divergence.index:
        let newBranch = new BranchesNode
        newBranch.initializeCommitment()
        current.snapshotChildCommitment(key[depth])
        current.branches[key[depth]] = newBranch
        when TraceLogs: echo &"At node {cast[uint64](current)}. Assigned new branch at '{key[depth].toHex}', depth {depth}, addr {cast[uint64](newBranch)}"
        current = newBranch
        inc(depth)
      current.snapshotChildCommitment(vn.stem[depth])
      current.branches[vn.stem[depth]] = vn
      when TraceLogs: echo &"At node {cast[uint64](current)}. Assigned ValuesNode at '{vn.stem[depth].toHex}', depth {depth}, addr {cast[uint64](vn)}"
      vn = nil # We can't use it

  current.snapshotChildCommitment(key[depth])

  # The current branch does not contain a ValuesNode at the required offset;
  # create one and store the value in it, as per the key's last byte offset
  if vn == nil:
    vn = newValuesNode(key, value)
    current.branches[key[depth]] = vn
    when TraceLogs: echo &"Created ValuesNode at depth {depth}, branch '{key[depth].toHex}', stem {vn.stem.toHex}, with value at slot '{key[^1].toHex}'"

  # Store the value in the existing ValuesNode, as per the key's last byte offset
  else:
    vn.setValue(key[^1], value)
    when TraceLogs: echo &"Added value to slot '{key[^1].toHex}'"



proc deleteValue*(node: BranchesNode, key: Bytes32): bool =
  ## Deletes the value associated with the given `key` from the tree.
  var current = node
  var depth = 0
  when TraceLogs: echo &"Deleting value for key {key.toHex}"

  # Walk down the tree until the branch closest to the key
  while current.branches[key[depth]] of BranchesNode:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Going down to branch '{key[depth].toHex}' at depth {depth}"
    current.snapshotChildCommitment(key[depth])
    current = current.branches[key[depth]].BranchesNode
    inc(depth)

  # If we reached a ValuesNode...
  var vn = current.branches[key[depth]].ValuesNode
  if vn != nil:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Found ValuesNode at branch '{key[depth].toHex}', depth {depth}, addr {cast[uint64](vn)}"
    when TraceLogs: echo &"    Stem: {vn.stem.toHex}"

    # If the stem differs from the key, we can't use that ValuesNode.
    # This means the value doesn't exist for the given key, so we return false.
    var divergence = vn.stem.zip(key).firstMatchAt(tup => tup[0] != tup[1])
    if divergence.found:
      return false

    # If the stem matches the key, we found the ValuesNode for the key.
    # We remove it by setting the branch to nil.
    current.snapshotChildCommitment(key[depth])
    vn.deleteValue(key[^1])

    return true

  # If no ValuesNode was found for the key, it means the value doesn't exist.
  return false