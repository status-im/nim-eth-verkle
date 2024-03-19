#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the math primitives used to compute Verkle commitments,
##  obtained from the Constantine library

import
  ../constantine/constantine/serialization/[codecs_banderwagon, codecs_status_codes],
  ../constantine/constantine/eth_verkle_ipa/eth_verkle_constants,
  ../constantine/constantine/hashes,
  ../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves,
  ../constantine/constantine/math/io/[io_bigints, io_fields],
  ../constantine/constantine/ethereum_verkle_primitives,
  ../constantine/constantine/ethereum_verkle_trees

export finite_fields.`==`

type
  Bytes32* = eth_verkle_constants.Bytes
    ## A 32-bytes blob that can represent a verkle key or value
  Field* = Fr[Banderwagon]
  Point* = eth_verkle_constants.EC_P


# Todo: can this be converted to a const?
var IdentityPoint*: Point
IdentityPoint.x.setZero()
IdentityPoint.y.setOne()
IdentityPoint.z.setOne()

var ipaConfig: IPASettings
discard ipaConfig.genIPAConfig()


proc ipaCommitToPoly*(poly: openArray[Field]): Point =
  var comm: Point
  comm.pedersen_commit_varbasis(ipaConfig.SRS, ipaConfig.SRS.len, poly, poly.len)
  return comm


proc banderwagonMultiMapToScalarField*(fields: var openArray[Field], points: openArray[Point]) =
  fields.batchMapToScalarField(points)


proc banderwagonMultiMapToScalarField*(fields: openArray[ptr Field], points: openArray[Point]) =
  var correctFields: seq[Fr[Banderwagon]] = @[]
  for field in fields:
    correctFields.add(Fr[Banderwagon](field[]))  # Assuming Fr[Banderwagon] can be initialized from a Field
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

proc fromBEBytes*(field: var Field, data: openArray[byte]) =
  var temp{.noinit.}: matchingOrderBigInt(Banderwagon)
  temp.unmarshal(data, bigEndian)
  field.fromBig(temp)

func serializePoint*(point: Point): Bytes32 =
  assert result.serialize(point) == CttCodecEccStatus.cttCodecEcc_Success

func zeroField*(): Field =
  result.setZero()