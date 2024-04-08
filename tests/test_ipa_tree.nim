#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.


import
  random,
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

  test "Make Verkle Multiproof for Multiple Leaf insertions":
    let leafCount = 100
    var keys = newSeq[Bytes32](1000)
    var tree = newTree()

    for i in 0 ..< leafCount:
      for j in 0 ..< 32:
        keys[i][j] = rand(255).byte
      
      tree.setValue(keys[i], fourtyKeyTest)

    tree.updateAllCommitments()

    var proof: VerkleProofUtils
    var postroot = newTree()
    var cis: seq[Point]
    var zis: seq[int]
    var yis: seq[Field]

    var interim_keys: seq[seq[byte]]
    interim_keys.add(keys[0].toSeq)
    # interim_keys.add(keys[1].toSeq)

    var time = cpuTime()
    var checker = false
    (proof, cis, zis, yis, checker) = tree.makeVKTMultiproof(postroot, interim_keys)
    var endTime = cpuTime()
    echo "Time taken to build proof elements from VKT and create multiproof ", endTime - time
    check checker == true
    discard postroot
    # var outs: seq[byte]
    # var outStem: seq[seq[byte]]
    # checker = false

    # var pel: ProofElements
    # checker = tree.getCommitmentsForMultiproof(interim_keys, pel, outs, outStem)

    var config: IPAConf
    discard config.generateIPAConfiguration()

    var time2 = cpuTime()
    checker = proof.Multipoint.verifyVKTMultiproof(config, cis, yis, zis)
    var endTime2 = cpuTime()
    echo "Time taken to verify that Multiproof ", endTime2 - time2
    check checker == true

  test "Make Verkle Multiproof for Multiple Leaf insertions 2":
    let leafCount = 100
    var keys = newSeq[Bytes32](1000)
    var tree = newTree()

    for i in 0 ..< leafCount:
      for j in 0 ..< 32:
        keys[i][j] = rand(255).byte
      
      var key = keys[i]
      tree.setValue(key, fourtyKeyTest)

    tree.updateAllCommitments()

    var proof: VerkleProofUtils
    var postroot = newTree()
    var cis: seq[Point]
    var zis: seq[int]
    var yis: seq[Field]

    var interim_keys = newSeq[seq[byte]](2)
    interim_keys[0] = keys[0].toSeq
    interim_keys[1] = keys[1].toSeq

    echo "Interim Keys"
    echo interim_keys.len

    echo "Len each interim key"
    echo interim_keys[0].len


    var time = cpuTime()
    var checker = false
    (proof, cis, zis, yis, checker) = tree.makeVKTMultiproof(postroot, interim_keys)

    echo "CIS ZIS YIS"
    echo cis.len
    echo zis.len
    echo yis.len

    var endTime = cpuTime()
    echo "Time taken to build proof elements from VKT and create multiproof ", endTime - time
    check checker == true
    discard postroot
    var outs: seq[byte]
    var outStem: seq[seq[byte]]
    checker = false

    var pel: ProofElements
    checker = tree.getCommitmentsForMultiproof(interim_keys, pel, outs, outStem)

    echo "Cis.len"
    echo pel.Cis.len

    echo "Zis.len"
    echo pel.Zis.len

    echo "Yis.len"
    echo pel.Yis.len

    var config: IPAConf
    discard config.generateIPAConfiguration()

    var time2 = cpuTime()
    checker = proof.Multipoint.verifyVKTMultiproof(config, pel.Cis, pel.Yis, pel.Zis)
    var endTime2 = cpuTime()
    echo "Time taken to verify that Multiproof ", endTime2 - time2
    check checker == true







      






