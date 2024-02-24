#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.


import
  unittest,
  ../eth_verkle/[math, encoding],
  ../eth_verkle/tree/[tree, operations, commitment],
  ../constantine/constantine/serialization/[codecs, codecs_banderwagon]

## Values to be used for testing
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

## ################################################################
##
##             Tests for Tree Insertion Correctness
##
## ################################################################
suite "Tree Insertion Tests":
  ## Tests if the Insertion into the root not
  ## is taking place at the expected position
  test "Insertion Into Root":
    var tree = newTree()
    tree.setValue(zeroKeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[zeroKeyTest[31]][]

  ## Tests if the insertion of two leafs
  ## into the root is taking place at the expected position
  test "Insert Two Leaves":
    var tree = newTree()
    tree.setValue(zeroKeyTest, testValue)
    tree.setValue(ffx32KeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[zeroKeyTest[31]][]
    check testValue == ((ValuesNode)tree.branches[255]).values[255][]

  ## Tests if the insertion of leafs
  ## into the last level is taking place at the expected position
  test "Insert Two Leaves Last Level":
    var tree = newTree()
    tree.setValue(zeroKeyTest, testValue)
    tree.setValue(oneKeyTest, testValue)
    check testValue == ((ValuesNode)tree.branches[0]).values[1][]
    check testValue == ((ValuesNode)tree.branches[0]).values[0][]

## ################################################################
##
##             Tests for Correct Commitment Updation
##
## ################################################################
suite "Commitment Tests":
  ## Tests to check is the commitment is updated
  ## after the insertion of a leaf
  ## and also to checks if caching of commitment is 
  ## working as expected
  ## TODO: make the nil check work 
  test "Cached Commitment Test":
    const
      key1 = fromHex(
        Bytes32, 
        "0x0105000000000000000000000000000000000000000000000000000000000000"
      )
      key2 = fromHex(
        Bytes32, 
        "0x0107000000000000000000000000000000000000000000000000000000000000"
      )
      key3 = fromHex(
        Bytes32, 
        "0x0405000000000000000000000000000000000000000000000000000000000000"
      )
      key4 = fromHex(
        Bytes32, 
        "0x0407000000000000000000000000000000000000000000000000000000000000"
      )

    var tree = newTree()

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

    ## TODO: Perform the not nil check
    ## currently the not nil check have been checked manually by printing the values
    # doAssert BranchesNode(tree.branches[1]).commitment != nil, "internal node has mistakenly cleared cached commitment"

## ################################################################
##
##               Tests for Deletion in Tree
##
## ################################################################
suite "Tree Deletion Tests":
  ## Tests if the deletion of a leaf is taking place
  ## correctly with proper removal of the leaf
  ## and updation of the commitment
  test "Delete Leaf Node":
    const
      key1 = fromHex(
        Bytes32,
        "0x0105000000000000000000000000000000000000000000000000000000000000"
      )
      key1p = fromHex(
        Bytes32,
        "0x0105000000000000000000000000000000000000000000000000000000000001"
      )
      key1pp = fromHex(
        Bytes32,
        "0x0105000000000000000000000000000000000000000000000000000000000081"
      )
      key2 = fromHex(
        Bytes32,
        "0x0107000000000000000000000000000000000000000000000000000000000000"
      )
      key3 = fromHex(
        Bytes32,
        "0x0405000000000000000000000000000000000000000000000000000000000000"
      )
    
    var tree = newTree()
    tree.setValue(key1, fourtyKeyTest)
    tree.setValue(key1p, fourtyKeyTest)
    tree.setValue(key1pp, fourtyKeyTest)
    tree.setValue(key2, fourtyKeyTest)
    tree.updateAllCommitments()

    var init = tree.commitment

    tree.setValue(key3, fourtyKeyTest)
    let err = tree.deleteValue(key3)
    doAssert err, "Deletion Failed"
    tree.updateAllCommitments()

    var final = tree.commitment
    doAssert init.serializePoint() == final.serializePoint(), "Deletion Inconsistent"
    doAssert tree.getValue(key3).isNil, "leaf hasnt been deleted"

  test "Test Delete Non-Existent Node should fail":
    ## Tests if the deletion of a non-existent leaf is taking place
    ## this test should fail, as the deletion of a non-existent leaf
    ## should not be allowed
    const
      key1 = fromHex(
        Bytes32, 
        "0x0105000000000000000000000000000000000000000000000000000000000000"
      )
      key2 = fromHex(
        Bytes32, 
        "0x0107000000000000000000000000000000000000000000000000000000000000"
      )
      key3 = fromHex(
        Bytes32, 
        "0x0405000000000000000000000000000000000000000000000000000000000000"
      )
    
    var tree = newTree()
    tree.setValue(key1, fourtyKeyTest)
    tree.setValue(key2, fourtyKeyTest)
    let err = tree.deleteValue(key3)
    doAssert (not err), "hould not fail when deleting a non-existent key"

  test "Test Delete Prune":
    ## Tests if the deletion of a leaf is taking place
    ## correctly with proper pruning of the data and commitment
    const
      key1 = fromHex(
        Bytes32, 
        "0x0105000000000000000000000000000000000000000000000000000000000000"
      )
      key2 = fromHex(
        Bytes32, 
        "0x0107000000000000000000000000000000000000000000000000000000000000"
      )
      key3 = fromHex(
        Bytes32, 
        "0x0405000000000000000000000000000000000000000000000000000000000000"
      )
      key4 = fromHex(
        Bytes32,
        "0x0407000000000000000000000000000000000000000000000000000000000000"
      )
      key5 = fromHex(
        Bytes32,
        "0x04070000000000000000000000000000000000000000000000000000000000FF"
      )
    
    var tree = newTree()
    tree.setValue(key1, fourtyKeyTest)
    tree.setValue(key2, fourtyKeyTest)
    tree.updateAllCommitments()

    var hashPostKey2 = tree.commitment

    tree.setValue(key3, fourtyKeyTest)
    tree.setValue(key4, fourtyKeyTest)
    tree.updateAllCommitments()

    var hashPostKey4 = tree.commitment

    tree.setValue(key5, fourtyKeyTest)
    tree.updateAllCommitments()

    var completeTreeHash = tree.commitment

    # Delete Key5
    doAssert tree.deleteValue(key5), "Unable to delete key5"
    tree.updateAllCommitments()

    var postHash = tree.commitment

    # Check that the deletion updated the root hash and that it's not
    # the same as the pre-deletion hash
    doAssert completeTreeHash.serializePoint() != postHash.serializePoint(), "Deletion did not update root hash"

    # The post deletion hash should be the same as the post key4 hash
    doAssert hashPostKey4.serializePoint() == postHash.serializePoint(), "deleting leaf #5 resulted in unexpected tree"

    # Delete key4 and key3
    doAssert tree.deleteValue(key4), "Unable to delete key4"
    doAssert tree.deleteValue(key3), "Unable to delete key3"
    tree.updateAllCommitments()

    postHash = tree.commitment

    # The post deletion hash should be different from the post key2 hash
    doAssert hashPostKey2.serializePoint() == postHash.serializePoint(), "deleting leaf #3 resulted in unexpected tree"

  test "Delete Unequal Path should fail":
    ## Test if deletion of unequal path is taking place
    ## for keys having similar path starting from the root
    const
      key1 = fromHex(
        Bytes32, 
        "0x0105000000000000000000000000000000000000000000000000000000000000"
      )
      key2 = fromHex(
        Bytes32, 
        "0x0107000000000000000000000000000000000000000000000000000000000000"
      )
      key3 = fromHex(
        Bytes32, 
        "0x0405000000000000000000000000000000000000000000000000000000000000"
      )
    var tree = newTree()
    tree.setValue(key1, fourtyKeyTest)
    tree.setValue(key3, fourtyKeyTest)
    tree.updateAllCommitments()
    
    doAssert (not tree.deleteValue(key2)), "errored during the deletion of non-existing key"

suite "Verkle Node Serialization Tests":
  test "Branch Node and Value Node Serialization Test":
    var test: array[32, byte] = fromHex(
      Bytes32,
      "0x3031323334353637383961626364656630313233343536373839616263646566"
    )
    var expected = "0x0180000000000000008000000000000000000000000000000000000000000000002949a242cb5e4ab784b6a0d081eb02b1ad9f1504effc9d702849b3c832b280d22326c61e36f849e6efe3414ebbb3279032e89035d7e455cba89b242a9dd8096f"
    
    var tree = newTree()
    tree.setValue(zeroKeyTest, test)
    tree.setValue(fourtyKeyTest, test)
    tree.updateAllCommitments()

    var arr: array[97, byte]
    doAssert arr.serialize(tree), "Failed to serialize node"
    doAssert arr.toHex() == expected, "Serialization Incorrect"

    let leaf0 = (ValuesNode)tree.branches[0]
    let leaf64 = (ValuesNode)tree.branches[64]

    let arr0 = leaf0.serialize()
    let arr64 = leaf64.serialize()

    doAssert arr0.toHex() == "0x02000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000357f4e31c18e01c589456e2ca1ef94c39129b0188f1d8b25f090f68aa1fa64660d9d8a7645d9a965fa65566d79378d224e3b6e7c3976925f13c8ccd08bcad20832ee6170dbd782063f8162c5c16a259ce24b1691bded3a6022ed0257cd5e4a66243c31e3f8ee7f5e0bcaf288a6c67ac2a43ad86960e41073ab83ce585c80172f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013031323334353637383961626364656630313233343536373839616263646566",
      "Serialization of leaf incorrect"
    doAssert arr64.toHex() == "0x024000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000003840da51ddde3bf1c6b76711c3e71c41970ca976744590e33b0e191db54b3656050e0812a7d5716c1e303d159292b035a5734c2c93ed3cbd25851e359ef08f6032ee6170dbd782063f8162c5c16a259ce24b1691bded3a6022ed0257cd5e4a66243c31e3f8ee7f5e0bcaf288a6c67ac2a43ad86960e41073ab83ce585c80172f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013031323334353637383961626364656630313233343536373839616263646566",
      "Serialization of leaf incorrect"

    # Reconstruction
    let res = parseNode(arr, 0)
    let resLeaf0 = parseNode(arr0, 1)
    let resLeaf64 = parseNode(arr64, 1)

    res.BranchesNode.branches[0] = resLeaf0.ValuesNode
    res.BranchesNode.branches[64] = resLeaf64.ValuesNode

    res.BranchesNode.updateAllCommitments()
    doAssert res.commitment.serializePoint() == tree.commitment.serializePoint(), "Reconstruction failed"

  
