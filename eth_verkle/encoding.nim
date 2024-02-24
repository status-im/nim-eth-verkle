#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ../constantine/constantine/serialization/[codecs, codecs_banderwagon, codecs_status_codes],
  ./tree/[tree, operations],
  ./math

const
  BranchRLPType:  byte = 1
  LeafRLPType:    byte = 2

const
  Mask: array[8, byte] = fromHex(array[8, byte], "0x8040201008040201")

  NodeTypeSize    = 1
  BitListSize     = 32
  NodeTypeOffSet  = 0

  # Internal Node Offsets
  InternalBitListOffSet     = NodeTypeOffSet + NodeTypeSize
  InternalCommitmentOffSet  = InternalBitListOffSet + BitListSize

  # Leaf Node Offsets
  LeafStemOffSet          = NodeTypeOffSet + NodeTypeSize
  LeafBitListOffSet       = LeafStemOffSet + 31              # 31 -> StemSize
  LeafCommitmentOffSet    = LeafBitListOffSet + BitListSize
  LeafC1CommitmentOffSet  = LeafCommitmentOffSet + 64        # 64 -> Uncompressed Banderwagon Point Size
  LeafC2CommitmentOffSet  = LeafC1CommitmentOffSet + 64      # 64 -> Uncompressed Banderwagon Point Size
  LeafChildrenOffSet      = LeafC2CommitmentOffSet + 64      # 64 -> Uncompressed Banderwagon Point Size

  BranchNodeSerializationSize = NodeTypeSize + BitListSize + 64

proc bit*(bitlist: openArray[byte], nr: int): bool =
  if len(bitlist) * 8 <= nr:
    return false
  return ((bitlist[nr div 8] and Mask[nr mod 8]) != 0)

## Serialize returns the serialized form of the internal node.
## The format is: <nodeType><bitlist><commitment>
proc serialize*(dst: var openArray[byte], node: BranchesNode): bool =
  for i in 0 ..< len(node.branches):
    if not node.branches[i].isNil():
      var t = dst[(i div 8)+InternalBitListOffSet] or Mask[(i mod 8)]
      dst[(i div 8)+InternalBitListOffSet] = t

  dst[NodeTypeOffSet] = BranchRLPType
  
  var arr: array[64, byte]
  if arr.serializeUncompressed(node.commitment) != cttCodecEcc_Success:
    return false

  for i in 0 .. 63:
    dst[InternalCommitmentOffSet + i] = arr[i]

  return true

proc serialize*(n: BranchesNode): seq[byte] =
  var res = newSeq[byte](BranchNodeSerializationSize)
  if res.serialize(n):
    return res
  return newSeq[byte](0)

proc serializeLeafWithUncompressedCommitments*(
    n: ValuesNode, 
    cBytes, c1Bytes, c2Bytes : array[64, byte]
  ): seq[byte] =
  var children: seq[byte]
  var bitlist: array[32, byte]
  for i, v in n.values:
    if not v.isNil():
      bitlist[i div 8] = bitlist[i div 8] or Mask[i mod 8]
      children.add(v[])

  var res: seq[byte]
  res.add(LeafRLPType)
  res.add(n.stem)
  res.add(bitlist)
  res.add(cBytes)
  res.add(c1Bytes)
  res.add(c2Bytes)
  res.add(children)

  return res

proc serialize*(n: ValuesNode): seq[byte] =
  var cBytes: array[3, array[64, byte]]
  discard cBytes.serializeBatchUncompressed([n.commitment, n.c1, n.c2])
  return serializeLeafWithUncompressedCommitments(n, cBytes[0], cBytes[1], cBytes[2])

proc parseValuesNode*(serialized: openArray[byte], depth: uint8): ValuesNode =
  var bitlist = serialized[LeafBitListOffSet ..< LeafBitListOffSet + BitListSize]
  var offset = LeafChildrenOffSet
  result = new ValuesNode

  for i in 0 ..< 31:
    result.stem[i] = serialized[LeafStemOffSet + i]
  result.depth = depth

  for i in 0 ..< 256:
    if bit(bitlist, i):
      doAssert(offset+32 <= len(serialized), "verkle payload is too short")
      var heapValue = new Bytes32
      for j in 0..<32:
        heapValue[j] = serialized[offset + j]
      result.values[i] = heapValue
      offset += 32

  var c1: array[64, byte]
  var c2: array[64, byte]
  var comm: array[64, byte]
  for i in 0 ..< 64:
    c1[i] = serialized[LeafC1CommitmentOffSet + i]
    c2[i] = serialized[LeafC2CommitmentOffSet + i]
    comm[i] = serialized[LeafCommitmentOffSet + i]

  doAssert result.c1.deserializeUncompressed(c1) == cttCodecEcc_Success, "failed to deserialize c1"
  doAssert result.c2.deserializeUncompressed(c2) == cttCodecEcc_Success, "failed to deserialize c2"
  doAssert result.commitment.deserializeUncompressed(comm) == cttCodecEcc_Success, "failed to deserialize commitment"
    
proc parseBranchesNode*(serialized: openArray[byte], depth: uint8): BranchesNode =
  result = newBranchesNode(depth)
  for i in InternalBitListOffSet ..< BitListSize+InternalBitListOffSet:
    for j in 0 ..< 8:
      if (serialized[i] and Mask[j]) != 0:
        result.branches[8*(i-InternalBitListOffSet)+j] = new BranchesNode
      else:
        result.branches[8*(i-InternalBitListOffSet)+j] = nil

  result.depth = depth
  var comm: array[64, byte]
  for i in 0 ..< 64:
    comm[i] = serialized[InternalCommitmentOffSet + i]
  doAssert result.commitment.deserializeUncompressed(comm) == cttCodecEcc_Success, "failed to deserialize commitment"

proc parseNode*(serialized: openArray[byte], depth: uint8): Node =
  if serialized[NodeTypeOffSet] == BranchRLPType:
    return parseBranchesNode(serialized, depth)
  elif serialized[NodeTypeOffSet] == LeafRLPType:
    return parseValuesNode(serialized, depth)
  else:
    return nil