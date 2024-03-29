#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  The main module. Provides some tests.

import
  std/[random, streams, os, times, strformat],
  unittest2,
  ../eth_verkle/[config, utils, math],
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
    "3300000000000000000000000000000000000000000000000000000000000001",
    "5500000000000000000000000000000000000000000000000000000000000000",
    "5500000000000000000000000000000000000000000000000000000000001100",
  ]
  const expectedRootCommitment3 = "4145d957eb624cb56af3861ebe0db2e9fee2de523b19aad55acf9085eb7cd158"


  const finalKvps = @[
    ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000011"),
    ("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f", "0000000000000000000000000000000000000000000000000000000000000002"),
    ("1100000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000003"),
    ("2200000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000004"),
    ("2211000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000005"),
    ("3300000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000006"),
    ("33000000000000000000000000000000000000000000000000000000000000ff", "0000000000000000000000000000000000000000000000000000000000000008"),
    ("4400000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000009"),
    ("4400000011000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000a"),
    ("4400000011000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000013"),
  ]



  iterator hexKvpsToBytes32(kvps: openArray[tuple[key: string, value: string]]):
      tuple[key: Bytes32, value: Bytes32] =
    for (hexKey, hexValue) in kvps:
      yield (hexToBytesArray[32](hexKey), hexToBytesArray[32](hexValue))


  test "sanity":

    # Populate tree and check root commitment
    when TraceLogs: echo "\n\n\nPopulating tree\n"
    var tree = newTree()
    for (key, value) in sampleKvps.hexKvpsToBytes32():
      tree.setValue(key, value)
    tree.updateAllCommitments()
    tree.printTree(newFileStream(stdout))
    check tree.serializeCommitment.toHex == expectedRootCommitment1

    # Update some nodes in the tree and check updated root commitment
    when TraceLogs: echo "\n\n\nAdding and modfying some key/values in the tree\n"
    for (key, value) in updateKvps.hexKvpsToBytes32():
      tree.setValue(key, value)
    tree.updateAllCommitments()
    #tree.printTree(newFileStream(stdout))
    check tree.serializeCommitment.toHex == expectedRootCommitment2

    # Delete some nodes in the tree and check updated root commitment
    when TraceLogs: echo "\n\n\nDeleting some key/values in the tree\n"
    for hexKey in deleteKvps:
      when TraceLogs: echo &"Deleting key {hexKey}"
      let key = hexToBytesArray[32](hexKey)
      check tree.deleteValue(key) == true
    tree.updateAllCommitments()
    #tree.printTree(newFileStream(stdout))
    check tree.serializeCommitment.toHex == expectedRootCommitment3

    # Populate a new tree with just the values remaining in the step above;
    # we expect the same commitment
    when TraceLogs: echo "\n\n\nCreating new tree with final key/values from steps above, structure and commitments should match previous step\n"
    var tree2 = newTree()
    for (key, value) in finalKvps.hexKvpsToBytes32():
      when TraceLogs: echo &"Adding {key.toHex} = {value.toHex}"
      tree2.setValue(key, value)
    tree2.updateAllCommitments()
    #tree2.printTree(newFileStream(stdout))
    check tree2.serializeCommitment.toHex == expectedRootCommitment3


  test "fetchKeys":
    var tree = newTree()
    for (key, value) in sampleKvps.hexKvpsToBytes32():
      tree.setValue(key, value)
    for (key, value) in sampleKvps.hexKvpsToBytes32():
      check tree.getValue(key)[] == value
    var missingKey1 = hexToBytesArray[32]("abcd000000000000000000000000000000000000000000000000000000000000")
    var missingKey2 = hexToBytesArray[32]("ef01234000000000000000000000000000000000000000000000000000000000")
    var missingKey3 = hexToBytesArray[32]("0000110000000000000000000000000000000000000000000000000000000000")
    check tree.getValue(missingKey1) == nil
    check tree.getValue(missingKey2) == nil
    check tree.getValue(missingKey3) == nil


  test "testDelNonExistingValues":
    var key1 = hexToBytesArray[32]("2200000000000000000000000000000000000000000000000000000000000000")
    var key2 = hexToBytesArray[32]("2211000000000000000000000000000000000000000000000000000000000000")
    var key3 = hexToBytesArray[32]("3300000000000000000000000000000000000000000000000000000000000000")
    var value = hexToBytesArray[32]("0000000000000000000000000000000000000000000000000000000000000000")
    var tree = newTree()
    tree.setValue(key1, value)
    tree.setValue(key2, value)
    check tree.deleteValue(key3) == false


  var random = initRand(seed = 1) # fixed seed for reproducible test

  proc makeRandomBytes32(): Bytes32 =
    result[ 0 ..<  8] = cast[array[8, byte]](random.next())
    result[ 8 ..< 16] = cast[array[8, byte]](random.next())
    result[16 ..< 24] = cast[array[8, byte]](random.next())
    result[24 ..< 32] = cast[array[8, byte]](random.next())


  test "randomValues_1000":
    ## Writes a larger-ish tree with random nodes to a file
    createDir "testResults"
    var startTime = cpuTime()

    var tree = newTree()
    for i in 0..<1000:
      tree.setValue(key = makeRandomBytes32(), value = makeRandomBytes32())

    var commitmentTime = cpuTime()
    tree.updateAllCommitments()
    var endTime = cpuTime()

    var file = open("testResults/randomValues_1000", fmWrite)
    defer: close(file)
    tree.printTree(newFileStream(file))
    echo "Tree dumped to 'testResults/randomValues_1000'"
    echo &"Time to populate tree (and compute leaf commitments): {commitmentTime - startTime:.3f} secs"
    echo &"Time to compute root commitment: {endTime - commitmentTime:.3f} secs"
