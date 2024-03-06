#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the basic verkle tree structure along with enumeration,
##  pretty printing and serialization methods

import
  std/[streams, tables],
  ../[utils, math, upstream]


type
  Node* = ref object of RootObj
    ## Base node type
    commitment*: Point
    depth*: uint8

  HashedNode* = ref Node
    ## TODO: Type that should vary from cl to cl, Node type that is retrieved from the disk

  BranchesNode* = ref object of Node
    ## Internal node in the tree that holds references to 256 child nodes (or nil-s)
    branches*: array[256, Node]
    commitmentsSnapshot*: ref Table[byte, Point]

  ValuesNode* = ref object of Node
    ## Leaf node in the tree that holds references to 256 values (or nil-s)
    stem*:   array[31, byte]
    values*: array[256, ref Bytes32]
    c1*, c2*: Point



func serializeCommitment*(node: Node): Bytes32 =
  ## Serializes the node's commitment
  node.commitment.serializePoint()



iterator enumerateTree*(node: BranchesNode):
    tuple[node: Node, index: uint8] =
  ## Iterates over all the nodes in the tree excluding values, depth-first

  # In order to keep this iterator an efficient second-class citizen, we can't
  # use recursion, hence we store our position in a stack
  var stack: seq[tuple[branch: BranchesNode, index: int]]
  stack.add((node, 0))

  # As long as we're not finished with the root node...
  while stack.len > 0:

    # peek at the current node we're working on
    let last = addr stack[^1]
    
    # If we finished traversing it, pop it from the stack. Next iteration we'll
    # continue with its parent.
    if last.index == last.branch.branches.len:
      discard stack.pop()
    else:
      # Fetch the next child node, and increase the index
      let child = last.branch.branches[last.index]
      inc(last.index)
      if child != nil:
        # If the child node is non-empty, return it
        yield (node: child, index: (last.index-1).uint8)

        # If the child is a BranchesNode, we push it to the stack and start
        # iterating its own children next iteration (starting from index 0)
        if child of BranchesNode:
          stack.add((child.BranchesNode, 0))



iterator enumerateModifiedTree*(node: BranchesNode):
    tuple[node: Node, index: uint8] {.closure.} =
  ## Iterates over all the nodes in the tree which were modified, or had one of
  ## their descendants modified
  if not node.commitmentsSnapshot.isNil:
    for index in node.commitmentsSnapshot.keys:
      let child = node.branches[index]
      yield (child, index)
      if child of BranchesNode:
        for item in enumerateModifiedTree(child.BranchesNode):
          yield item



iterator enumerateValues*(node: BranchesNode):
    tuple[key: Bytes32, value: ref Bytes32] =
  ## Iterates over all the key-value pairs in the tree
  
  # Iterate over all nodes in the tree (excluding values)
  for n, _ in node.enumerateTree():
    if n of ValuesNode:
      # When we reach a ValuesNode, iterate over all its non-nil values and
      # return them. We need to regenerate the key of each value by appending
      # its offset to the stem.
      for index, value in n.ValuesNode.values.pairs:
        if value != nil:
          var key:Bytes32
          key[0..<31] = n.ValuesNode.stem
          key[31] = index.byte
          yield (key, value)


proc printTreeValues*(node: BranchesNode, stream: Stream) =
  ## Writes all the key-value pairs into the given `stream`, in the form:
  ## 
  ## (hex key) --> (hex value)
  ## 
  ## (hex key) --> (hex value)
  for key, value in node.enumerateValues():
    stream.writeAsHex(key)
    stream.write(" --> ")
    stream.writeAsHex(value[])
    stream.writeLine()


proc `$`*(node: BranchesNode): string =
  ## Returns all the key-value pairs in the tree in the form:
  ## 
  ## (hex key) --> (hex value)
  ## 
  ## (hex key) --> (hex value)
  var stream = newStringStream()
  printTreeValues(node, stream)
  stream.flush()
  stream.data


proc printTree*(node: BranchesNode, stream: Stream) =
  ## Writes all the nodes and values into the given `stream`.
  ## Outputs a line for each branch, stem and value in the tree, indented by
  ## depth, along with their commitment.
  stream.write("<Tree root>                                                           Branch. Commitment: ")
  stream.writeAsHex(node.commitment.serializePoint)
  stream.writeLine()
  for n, parentIndex in node.enumerateTree():
    for _ in 0 ..< n.depth.int:
      stream.write("  ")
    stream.writeAsHex(parentIndex.byte)
    if n of BranchesNode:
      for _ in n.depth .. 33:
        stream.write("  ")
      stream.write("Branch. Commitment: ")
      stream.writeAsHex(n.commitment.serializePoint)
      stream.writeLine()
    elif n of ValuesNode:
      stream.writeAsHex(n.ValuesNode.stem[n.depth..^1])
      stream.write("      Leaves. Commitment: ")
      stream.writeAsHex(n.commitment.serializePoint)
      stream.writeLine()
      for valueIndex, value in n.ValuesNode.values.pairs:
        if value != nil:
          stream.write("                                                                ")
          stream.writeAsHex(valueIndex.byte)
          stream.write("    Leaf.   Value:      ")
          stream.writeAsHex(value[])
          stream.writeLine()
