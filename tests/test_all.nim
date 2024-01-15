#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  The main module. Provides some tests.

import
  std/[random, streams, os, sequtils],
  unittest2,
  ../eth_verkle/utils,
    ../eth_verkle/tree/[tree, operations, commitment]

createDir "testResults"

suite "main":

  var random = initRand(seed = 1) # fixed seed for reproducible test

  proc makeRandomBlob32(): array[32, byte] =
    result[ 0 ..<  8] = cast[array[8, byte]](random.next())
    result[ 8 ..< 16] = cast[array[8, byte]](random.next())
    result[16 ..< 24] = cast[array[8, byte]](random.next())
    result[24 ..< 32] = cast[array[8, byte]](random.next())

  proc toBlob32(str: string): Bytes32 =
    result[0..^1] = str.fromHex

  iterator hexKvpsToBlob32(kvps: openArray[tuple[key: string, value: string]]):
      tuple[key: Bytes32, value: Bytes32] =
    for (hexKey, hexValue) in kvps:
      yield (hexKey.toBlob32, hexValue.toBlob32)


  let sampleKvps = @[
    ("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000123456789abcdef0123456789abcdef"),
    ("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f", "0000000000000000000000000000000000000000000000000000000000000002"),
    ("1100000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000003"),
    ("2200000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000004"),
    ("2211000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000005"),
    ("3300000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000006"),
    ("3300000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000007"),
    ("33000000000000000000000000000000000000000000000000000000000000ff", "0000000000000000000000000000000000000000000000000000000000000008"),
    ("4400000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000009"),
    ("4400000011000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000a"),
    ("5500000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000b"),
    ("5500000000000000000000000000000000000000000000000000000000001100", "000000000000000000000000000000000000000000000000000000000000000c"),
  ]
  let updateKvps = @[
    ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000011"),
    ("1100000000000000000000000000000000000000000000000000000000010000", "0000000000000000000000000000000000000000000000000000000000000012"),
    ("4400000011000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000013"),
  ]
  let deleteKvps = @[
    "1100000000000000000000000000000000000000000000000000000000010000",
    "2211000000000000000000000000000000000000000000000000000000000000",
    "5500000000000000000000000000000000000000000000000000000000001100"
  ]


  proc printAndTestCommitments(tree: BranchesNode) =
    tree.updateAllCommitments()
    #echo $tree  # print keys --> values
    tree.printTree(newFileStream(stdout)) # prints full tree
    var expectedCommitment = tree.enumerateValues.toSeq.foldl(a + b.value[^1], 0.byte)
    #check tree.commitment.X[0] == expectedCommitment


  test "testOnSave":

    echo "Populating tree...\n"
    var tree = new BranchesNode
    for (key, value) in sampleKvps.hexKvpsToBlob32():
      tree.setValue(key, value)
    tree.printAndTestCommitments()

#     echo "\n\nUpdating tree...\n\n"
#     for (key, value) in updateKvps.hexKvpsToBlob32():
#       tree.setValue(key, value)
#     tree.printAndTestCommitments()

#     echo "\n\nDeleting nodes:"
#     echo deleteKvps.foldl(a & "  " & b & "\n", "")
#     for key in deleteKvps:
#       discard tree.deleteValue(key.toBlob32)
#     tree.printAndTestCommitments()


#   test "testDelValues":
#     ## Makes a small sample tree
#     var tree = new BranchesNode
#     var key, value: Bytes32
#     for (keyHex, valueHex) in sampleKvps:
#       key[0..^1] = keyHex.fromHex
#       value[0..^1] = valueHex.fromHex
#       tree.setValue(key, value)

#     ## Deletes some values
#     key[0..^1] = sampleKvps[6][0].fromHex
#     check tree.deleteValue(key) == true
#     key[0..^1] = sampleKvps[7][0].fromHex
#     check tree.deleteValue(key) == true
#     key[0..^1] = sampleKvps[8][0].fromHex
#     check tree.deleteValue(key) == true
#     tree.printTree(newFileStream(stdout)) # prints full tree

#   test "testDelNonExistingValues":
#     var key1, key2, key3, value: Bytes32
#     key1[0..^1] = "2200000000000000000000000000000000000000000000000000000000000000".fromHex
#     key2[0..^1] = "2211000000000000000000000000000000000000000000000000000000000000".fromHex
#     key3[0..^1] = "3300000000000000000000000000000000000000000000000000000000000000".fromHex 
#     value[0..^1] = "0000000000000000000000000000000000000000000000000000000000000000".fromHex 

#     var tree = new BranchesNode
#     tree.setValue(key1, value)
#     tree.setValue(key2, value)

#     check tree.deleteValue(key3) == false

#   test "randomValues_10000":
#     ## Writes a larger tree with random nodes to a file
#     var tree = new BranchesNode
#     for i in 0..10000:
#       tree.setValue(key = makeRandomBlob32(), value = makeRandomBlob32())
#     tree.updateAllCommitments()
#     var file = open("testResults/randomValues_10000", fmWrite)
#     defer: close(file)
#     tree.printTree(newFileStream(file))
#     echo "Tree dumped to 'testResults/randomValues_10000'"
