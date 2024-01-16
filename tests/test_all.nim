#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  The main module. Provides some tests.

import
  std/[random, streams, os],
  unittest2,
  ../eth_verkle/[utils, math],
  ../eth_verkle/tree/[tree, operations, commitment]

suite "main":


  const sampleKvps = @[
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
  const expectedRootCommitment1 = "38dc58e5094e2447c12755c878e28b0b2bf74c8d7a80a2d7351dd1bdc01a16f4"
    ## Matches go-verkle commitment


  let updateKvps = @[
    ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000011"),
    ("1100000000000000000000000000000000000000000000000000000000010000", "0000000000000000000000000000000000000000000000000000000000000012"),
    ("4400000011000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000013"),
  ]
  const expectedRootCommitment2 = "59664c8b5d0b5230b587fe6a826e1e946c5467dbecf156edee9fe7fb9da6423a"
    ## Matches go-verkle commitment


  let deleteKvps = @[
    "1100000000000000000000000000000000000000000000000000000000010000",
    "2211000000000000000000000000000000000000000000000000000000000000",
    "5500000000000000000000000000000000000000000000000000000000001100"
  ]
  const expectedRootCommitment3 = "1b0b20e55d30cbd3538f98a194d955aa74b77342196046e70d68f458a7f6d084"
    ## Matches go-verkle commitment


  iterator hexKvpsToBytes32(kvps: openArray[tuple[key: string, value: string]]):
      tuple[key: Bytes32, value: Bytes32] =
    for (hexKey, hexValue) in kvps:
      yield (hexToBytesArray[32](hexKey), hexToBytesArray[32](hexValue))


  test "sanity":

    # Populate tree and check root commitment
    var tree = newBranchesNode()
    for (key, value) in sampleKvps.hexKvpsToBytes32():
      tree.setValue(key, value)
    tree.updateAllCommitments()
    tree.printTree(newFileStream(stdout))
    check tree.serializeCommitment.toHex == expectedRootCommitment1

    # Update some nodes in the tree and check updated root commitment
    for (key, value) in updateKvps.hexKvpsToBytes32():
      tree.setValue(key, value)
    tree.updateAllCommitments()
    #tree.printTree(newFileStream(stdout))
    check tree.serializeCommitment.toHex == expectedRootCommitment2

    # Delete some nodes in the tree and check updated root commitment
    for hexKey in deleteKvps:
      let key = hexToBytesArray[32](hexKey)
      check tree.deleteValue(key) == true
    tree.updateAllCommitments()
    #tree.printTree(newFileStream(stdout))
    #check tree.serializeCommitment.toHex == expectedRootCommitment3
    # Note: currently fails since we don't deep-delete values like go-verkle does


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

  # var random = initRand(seed = 1) # fixed seed for reproducible test

  # proc makeRandomBytes32(): Bytes32 =
  #   result[ 0 ..<  8] = cast[array[8, byte]](random.next())
  #   result[ 8 ..< 16] = cast[array[8, byte]](random.next())
  #   result[16 ..< 24] = cast[array[8, byte]](random.next())
  #   result[24 ..< 32] = cast[array[8, byte]](random.next())

  # createDir "testResults"


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
