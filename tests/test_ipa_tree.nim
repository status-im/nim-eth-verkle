#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.


import
  unittest,
  sequtils,
  times,
  ../eth_verkle/ipa/ipa_proof,
  ../eth_verkle/[math, encoding],
  ../eth_verkle/tree/[tree, operations, commitment]

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
##     Tests for constructing Verkle Multiproof from Empty Tree
##
## ################################################################
suite "Test Proof of Empty Tree":
  test "Make Verkle Multiproof out of Populated Verkle Trie Correctly":
    var tree = newTree()
    tree.setValue(zeroKeyTest, zeroKeyTest)
    tree.setValue(oneKeyTest, zeroKeyTest)
    tree.setValue(ffx32KeyTest, zeroKeyTest)

    var postroot = newTree()

    var proof: VerkleProofUtils

    var cis: seq[Point]
    var zis: seq[int]
    var yis: seq[Field]

    var checker = false
    var values: seq[seq[byte]]
    values.add(ffx32KeyTest.toSeq)

    var time = cpuTime()
    (proof, cis, zis, yis, checker) = tree.makeVKTMultiproof(postroot, values)
    var endTime = cpuTime()
    echo "Time taken to build proof elements from VKT and create multiproof ", endTime - time
    check checker == true


    var config: IPAConf
    discard config.generateIPAConfiguration()

    var time2 = cpuTime()
    checker = proof.Multipoint.verifyVKTMultiproof(config, cis, yis, zis)
    var endTime2 = cpuTime()
    echo "Time taken to verify that Multiproof ", endTime2 - time2
    check checker == true


