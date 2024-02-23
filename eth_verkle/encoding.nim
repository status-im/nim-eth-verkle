#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ../constantine/constantine/serialization/[codecs, codecs_banderwagon, codecs_status_codes],
  ../constantine/constantine/eth_verkle_ipa/eth_verkle_constants,
  ../constantine/constantine/hashes,
  ../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves,
  ../constantine/constantine/math/io/[io_bigints, io_fields],
  ../constantine/constantine/ethereum_verkle_primitives,
  ../constantine/constantine/ethereum_verkle_trees,
  ./tree/[tree, operations, commitment]

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