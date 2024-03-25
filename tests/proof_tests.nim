#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.


import
  unittest,
  ./test_tree,
  ../eth_verkle/ipa/[
    execution_witness,
    ipa_proof,
    poststatetree,
    prestatetree,
    verkle_proof_utils
  ],
  ../eth_verkle/[math, encoding, upstream],
  ../eth_verkle/tree/[tree, operations, commitment],
  ../constantine/constantine/serialization/codecs

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
  test "Make Verkle Multiproof out of Empty Tree Correctly":
    var tree = newTree()

    var postroot = newTree()
    var proof: VerkleProofUtils
    var cis: seq[EC_P]
    var yis: seq[Fr[Banderwagon]] 
    var zis: seq[int]
    var checker = false

    var values: KeyList
    for i in 0 ..< 32:
      values[0][i] = ffx32KeyTest[i]

    (proof, cis, yis, zis, checker) = tree.makeVKTMultiproof(postroot, values)
    check checker == true

    var ipaConfig: IPASettings
    discard ipaConfig.genIPAConfig()

    var stat = false
    stat = proof.verifyVerkleProof(ipaConfig, cis, zis, yis)
    check stat == true


