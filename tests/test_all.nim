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
  ../eth_verkle/utils,
  ../eth_verkle/tree/[tree, operations]

createDir "testResults"

suite "main":

  var random = initRand(seed = 1) # fixed seed for reproducible test

  proc makeRandomBlob32(): array[32, byte] =
    result[ 0 ..<  8] = cast[array[8, byte]](random.next())
    result[ 8 ..< 16] = cast[array[8, byte]](random.next())
    result[16 ..< 24] = cast[array[8, byte]](random.next())
    result[24 ..< 32] = cast[array[8, byte]](random.next())

  let sampleKvps = @[
    ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("1100000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("2200000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("2211000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("3300000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("3300000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("33000000000000000000000000000000000000000000000000000000000000ff", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("4400000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("4400000011000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("5500000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("5500000000000000000000000000000000000000000000000000000000001100", "0000000000000000000000000000000000000000000000000000000000000000"),
  ]


  test "testOnSave":
    ## Prints a small sample tree
    var tree = new BranchesNode
    for (keyHex, valueHex) in sampleKvps:
      var key, value: Bytes32
      key[0..^1] = keyHex.fromHex
      value[0..^1] = valueHex.fromHex
      tree.setValue(key, value)
    #echo $tree  # print keys --> values
    tree.printTree(newFileStream(stdout)) # prints full tree

  test "testDelValues":
    ## Makes a small sample tree
    var tree = new BranchesNode
    var key, value: Bytes32
    for (keyHex, valueHex) in sampleKvps:
      key[0..^1] = keyHex.fromHex
      value[0..^1] = valueHex.fromHex
      tree.setValue(key, value)

    ## Deletes some values
    key[0..^1] = sampleKvps[6][0].fromHex
    doAssert tree.deleteValue(key) == true
    key[0..^1] = sampleKvps[7][0].fromHex
    doAssert tree.deleteValue(key) == true
    key[0..^1] = sampleKvps[8][0].fromHex
    doAssert tree.deleteValue(key) == true
    tree.printTree(newFileStream(stdout)) # prints full tree

  test "testDelNonExistingValues":
    var key1, key2, key3, value: Bytes32
    key1[0..^1] = "2200000000000000000000000000000000000000000000000000000000000000".fromHex
    key2[0..^1] = "2211000000000000000000000000000000000000000000000000000000000000".fromHex
    key3[0..^1] = "3300000000000000000000000000000000000000000000000000000000000000".fromHex 
    value[0..^1] = "0000000000000000000000000000000000000000000000000000000000000000".fromHex 

    var tree = new BranchesNode
    tree.setValue(key1, value)
    tree.setValue(key2, value)

    doAssert tree.deleteValue(key3) == false

  test "randomValues_10000":
    ## Writes a larger tree with random nodes to a file
    var tree = new BranchesNode
    for i in 0..10000:
      tree.setValue(key = makeRandomBlob32(), value = makeRandomBlob32())
    tree.printTree(newFileStream(open("testResults/randomValues_10000", fmWrite)))
    echo "Tree dumped to 'testResults/randomValues_10000'"
