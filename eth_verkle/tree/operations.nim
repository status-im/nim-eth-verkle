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
  ./tree

when TraceLogs: import std/strformat

proc setValue(node: ValuesNode, index: byte, value: Bytes32) =
  ## Heap-allocates the given `value` and stores it at the given `index`
  var heapValue = new Bytes32
  heapValue[] = value
  node.values[index] = heapValue


# TODO: prevent setting a value from a non-root node
proc setValue*(node: BranchesNode, key: Bytes32, value: Bytes32) =
  ## Stores the given `value` in the tree at the given `key`
  var current = node
  var depth = 0
  when TraceLogs: echo &"Setting {key.toHex} --> {value.toHex}"

  # Walk down the tree till the branch closest to the key
  while current.branches[key[depth]] of BranchesNode:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Going down to branch '{key[depth].toHex}' at depth {depth}"
    current = current.branches[key[depth]].BranchesNode
    inc(depth)

  # If we reached a ValuesNode...
  var vn = current.branches[key[depth]].ValuesNode
  if vn != nil:
    when TraceLogs: echo &"At node {cast[uint64](current)}. Found ValuesNode at branch '{key[depth].toHex}', depth {depth}, addr {cast[uint64](vn)}"
    when TraceLogs: echo &"    Stem: {vn.stem.toHex}"

    # If the stem differs from the key, we can't use that ValuesNode. We need to
    # insert intermediate branches till the point they diverge, pushing down the
    # current ValuesNode, and the proceed to create a new ValuesNode
    var divergence = vn.stem.zip(key).firstMatchAt(tup => tup[0] != tup[1])
    if divergence.found:
      when TraceLogs: echo &"    Key:  {key.toHex}"
      when TraceLogs: echo &"    Found difference at depth {divergence.index}"
      while depth < divergence.index:
        let newBranch = new BranchesNode
        current.branches[key[depth]] = newBranch
        when TraceLogs: echo &"At node {cast[uint64](current)}. Replaced ValuesNode with a new branch at '{key[depth].toHex}', depth {depth}, new branch addr {cast[uint64](newBranch)}"
        current = newBranch
        inc(depth)
        current.branches[vn.stem[depth]] = vn
        when TraceLogs: echo &"At node {cast[uint64](current)}. Assigned ValuesNode to new branch at '{vn.stem[depth].toHex}', depth {depth}, ValuesNodes addr {cast[uint64](vn)}"
      vn = nil # We can't use it

  # The current branch does not contain a ValuesNode at the required offset;
  # create one
  if vn == nil:
    vn = new ValuesNode
    vn.stem[0..<31] = key[0..<31]
    current.branches[key[depth]] = vn
    when TraceLogs: echo &"Created ValuesNode at depth {depth}, branch '{key[depth].toHex}', stem {vn.stem.toHex}"

  # Store the value in the ValuesNode, as per the key's last byte offset
  vn.setValue(key[^1], value)
  when TraceLogs: echo &"Added value to slot '{key[^1].toHex}'"
