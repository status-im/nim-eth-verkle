#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the math primitives used to compute Verkle commitments,
##  obtained from the Constantine library

import
  tables,
  ../constantine/constantine/hashes,
  ../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves,
  ../constantine/constantine/curves_primitives,
  ../constantine/constantine/math/io/[io_bigints, io_fields],
  ../constantine/constantine/serialization/[codecs_banderwagon, codecs_status_codes],
  ../constantine/constantine/ethereum_verkle_primitives,
  ../constantine/constantine/ethereum_verkle_trees

export finite_fields.`==`

export ethereum_verkle_trees.Point
export ethereum_verkle_trees.Field

type
  Bytes32* = ethereum_verkle_trees.Bytes
    ## A 32-bytes blob that can represent a verkle key or value
  Multipoint* = ethereum_verkle_trees.MultiProof
  IPAConf* = ethereum_verkle_trees.IPASettings
  SerializedMultipoint* = ethereum_verkle_trees.VerkleMultiproofSerialized


const VKTDomain* = ethereum_verkle_trees.VerkleDomain
#########################################################################
#
#                 Verkle Proof Items and it's Utilities
#
#########################################################################

type KeyList* = seq[seq[byte]]

type ProofElements* = object
  Cis*:                        seq[Point]
  Zis*:                        seq[int]
  Yis*:                        seq[Field]
  Fis*:                        seq[seq[Field]]
  Vals*:                       seq[seq[byte]]
  CommByPath*:                 Table[string, Point]
  cisZisTup*:                  Table[Bytes32, Table[int, bool]]

#########################################################################
#
#  Verkle Proof Types required to Interface Eth Verkle IPA in Constantine
#
#########################################################################

const IpaProofDepth*: int = 8

type IPAProofVkt* = object
  C_L*: array[IpaProofDepth, array[32, byte]]
  C_R*: array[IpaProofDepth, array[32, byte]]
  FinalEval*: array[32, byte]

#########################################################
#
#  Helper types to rebuild the partial view of the tree
#
#########################################################

type VerkleProof* = object
  ## OtherStems stores the stems to which the leaf notes don't match initially in a Proof of Presence check.
  ## DepthExtensionPresent stores the depth to which the leaf is present
  ## Corresponding to a branch of the partial view
  ## CommitmentsByPath is a DFS-style walk of the Verkle Trie with each required commitment
  ## D + IPAProof is everything that the verifier needs to ensure that the partial view of
  ## The trie that is built is indeed correct.
  OtherStems*: seq[array[31, byte]]
  DepthExtensionPresent*: seq[byte]
  CommitmentsByPath*: seq[array[32, byte]]
  D*: array[32, byte]
  IPAProofPView*: IPAProofVkt 

type VerkleProofUtils* = object
  ## Multipoint argument
  ## ExtentionStatus for each stem
  ## Commitments sorted lexicographically by their path in the tree
  ## Stems proving the `to be proved` stem is absent
  Multipoint*: Multipoint
  ExtensionStatus*: seq[byte]
  Cs*: seq[Point]
  PoaStems*: seq[seq[byte]]
  Keys*: seq[seq[byte]]
  PreStateValues*: seq[seq[byte]]
  PostStateValues*: seq[seq[byte]]

type SuffixStateDiff* = object
  Suffix*: byte
  CurrentVal*: array[32, byte]
  NewVal*: array[32, byte]

type SuffixStateDiffs* = seq[SuffixStateDiff]

const StemSize*: int = 31
type Stem* = array[StemSize, byte]

type StemStateDiff* = object
  Stem*: seq[byte]
  SuffixDiffsInVKT*: SuffixStateDiffs

type StateDiff* = seq[StemStateDiff]

type 
  StemInfo* = object
    depth*, stemType*: byte
    stat_c1*, stat_c2*: bool
    values*: Table[byte, seq[byte]]
    stem*: seq[byte]

var IdentityPoint*: Point
IdentityPoint.x.setZero()
IdentityPoint.y.setOne()
IdentityPoint.z.setOne()

var ipaConfig: IPAConf
discard ipaConfig.genIPAConfig()

proc strToBytes* (bytearr: var openArray[byte], s: static string)=
  for i in 0 ..< s.len:
    bytearr[i] = byte s[i]

proc VKTMultiproofSerializer*(serializedVerkleMultiproof: var SerializedMultipoint, proof: var Multipoint): bool=
  var checker = false
  checker = serializedVerkleMultiproof.serializeVerkleMultiproof(proof)
  return checker

proc VKTMultiproofDeserializer*(proof: var Multipoint, serializedVerkleMultiproof: var SerializedMultipoint,): bool=
  var checker = false
  checker = proof.deserializeVerkleMultiproof(serializedVerkleMultiproof)
  return checker

proc createVKTMultiproof*(mprv: var Multipoint, ipaConfig: IPAConf, Cis: openArray[Point], Fis: array[VKTDomain, array[VKTDomain, Field]], Zis: openArray[int]): bool=
  var checker = false
  var transcript {.noInit.}: sha256
  var label: seq[byte]
  label.strToBytes("vt")
  transcript.newTranscriptGen(label)
  checker = mprv.createMultiproof(transcript, ipaConfig, Cis, Fis, Zis)
  return checker

proc verifyVKTMultiproof*(mprv: var Multipoint, ipaConfig: IPAConf, Cis: openArray[Point], Yis: openArray[Field], Zis: openArray[int]): bool=
  var checker = false
  var transcript {.noInit.}: sha256
  var label: seq[byte]
  label.strToBytes("vt")
  transcript.newTranscriptGen(label)
  checker = mprv.verifyMultiproof(transcript, ipaConfig, Cis, Yis, Zis)
  return checker

proc generateIPAConfiguration* (ipaConfig: var IPAConf): bool=
  var checker = false
  checker = ipaConfig.genIPAConfig()
  return checker

proc ipaCommitToPoly*(poly: array[256, Field]): Point =
  var comm: Point
  comm.pedersen_commit_varbasis(ipaConfig.SRS, ipaConfig.SRS.len, poly, poly.len)
  return comm

proc banderwagonMultiMapToScalarField*(fields: var openArray[Field], points: openArray[Point]) =
  fields.batchMapToScalarField(points)


proc banderwagonMultiMapToScalarField*(fields: openArray[ptr Field], points: openArray[Point]) =
  var correctFields: seq[Field] = @[]
  for field in fields:
    correctFields.add(Field(field[]))  # Assuming Field can be initialized from a Field
  correctFields.batchMapToScalarField(points)
  for i in 0..<correctFields.len:
    fields[i][] = correctFields[i]


proc banderwagonAddPoint*(dst: var Point, src: Point) =
  dst.sum(dst, src)


proc bandesnatchSubtract*(x, y: Field): Field =
  result.diff(x, y)


# SetUint64 z = v, sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
proc bandesnatchSetUint64*(z: var Field, v: uint64) =
  z.fromInt(int(v))


proc fromLEBytes*(field: var Field, data: openArray[byte]) =
  var temp{.noinit.}: matchingOrderBigInt(Banderwagon)
  temp.unmarshal(data, littleEndian)
  field.fromBig(temp)
  

func serializePoint*(point: Point): Bytes32 =
  assert result.serialize(point) == CttCodecEccStatus.cttCodecEcc_Success

func deserializePoint*(bytearr: var Bytes32): Point =
  assert result.deserialize_vartime(bytearr) == CttCodecEccStatus.cttCodecEcc_Success
