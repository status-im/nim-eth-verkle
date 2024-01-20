#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  The main module. Provides some tests.

import
  unittest,
  ../eth_verkle/math,
  ../eth_verkle/tree/[tree, operations, commitment],
  ../constantine/constantine/serialization/codecs

const
    testValue = fromHex(
        Bytes32, 
        "0x0123456789abcdef0123456789abcdef"
    )
    zeroKeyTest = fromHex(
        Bytes32, 
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    )
    oneKeyTest = fromHex(
        Bytes32, 
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    )
    # forkOneKeyTest = fromHex(
    #     Bytes32, 
    #     "0x0001000000000000000000000000000000000000000000000000000000000001"
    # )
    fourtyKeyTest = fromHex(
        Bytes32, 
        "0x4000000000000000000000000000000000000000000000000000000000000000"
    )
    ffx32KeyTest = fromHex(
        Bytes32, 
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )


suite "Tree Insertion Tests":

  test "Insertion Into Root":
    var tree = newBranchesNode()
    tree.setValue(zeroKeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[zeroKeyTest[31]][]

  test "Insert Two Leaves":
    var tree = newBranchesNode()
    tree.setValue(zeroKeyTest, testValue)
    tree.setValue(ffx32KeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[zeroKeyTest[31]][]
    check testValue == ((ValuesNode)tree.branches[255]).values[255][]

  test "Insert Two Leaves Last Level":
    var tree = newBranchesNode()
    tree.setValue(zeroKeyTest, testValue)
    tree.setValue(oneKeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[1][]
    check testValue == ((ValuesNode)tree.branches[0]).values[0][]

suite "Commitment Tests":

  test "Cached Commitment Test":
    
    var
      key1: Bytes32 = fromHex(Bytes32, "0x0105000000000000000000000000000000000000000000000000000000000000")
      key2: Bytes32 = fromHex(Bytes32, "0x0107000000000000000000000000000000000000000000000000000000000000")
      key3: Bytes32 = fromHex(Bytes32, "0x0405000000000000000000000000000000000000000000000000000000000000")
      key4: Bytes32 = fromHex(Bytes32, "0x0407000000000000000000000000000000000000000000000000000000000000")

    var tree = newBranchesNode()

    tree.setValue(key1, fourtyKeyTest)
    tree.setValue(key2, fourtyKeyTest)
    tree.setValue(key3, fourtyKeyTest)
    tree.updateAllCommitments()

    var oldRoot = tree.commitment
    var oldInternal = ((ValuesNode)tree.branches[4]).commitment


    tree.setValue(key4, fourtyKeyTest)
    tree.updateAllCommitments()

    var newRoot = tree.commitment
    var newInternal = ((BranchesNode)tree.branches[4]).commitment

    doAssert oldRoot.serializePoint() != newRoot.serializePoint(), "root has stale commitment"
    doAssert oldInternal.serializePoint() != newInternal.serializePoint(), "internal node has stale commitment"

    # TODO: make the nil check work
    # doAssert isNil(BranchesNode(tree.branches[1]).commitment), "internal node has mistakenly cleared cached commitment"

  
