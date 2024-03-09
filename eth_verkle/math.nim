#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the math primitives used to compute Verkle commitments,
##  obtained from the Constantine library

import
  upstream,
  ../constantine/constantine/serialization/[codecs_banderwagon, codecs_status_codes],
  ../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves,
  ../constantine/constantine/math/io/[io_bigints, io_fields],
  ../constantine/constantine/ethereum_verkle_primitives

export finite_fields.`==`


var IdentityPoint*: EC_P
IdentityPoint.x.setZero()
IdentityPoint.y.setOne()
IdentityPoint.z.setOne()

var ipaConfig: IPASettings
discard ipaConfig.genIPAConfig()

proc ipaCommitToPoly*(poly: array[256, Fr[Banderwagon]]): EC_P =
  var comm: EC_P
  comm.pedersen_commit_varbasis(ipaConfig.SRS, ipaConfig.SRS.len, poly, poly.len)
  return comm


proc banderwagonMultiMapToScalarField*(fields: var openArray[Fr[Banderwagon]], points: openArray[EC_P]) =
  fields.batchMapToScalarField(points)


proc banderwagonMultiMapToScalarField*(fields: openArray[ptr Fr[Banderwagon]], points: openArray[EC_P]) =
  var correctFields: seq[Fr[Banderwagon]] = @[]
  for field in fields:
    correctFields.add(Fr[Banderwagon](field[]))  # Assuming Fr[Banderwagon] can be initialized from a Fr[Banderwagon]
  correctFields.batchMapToScalarField(points)
  for i in 0..<correctFields.len:
    fields[i][] = correctFields[i]


proc banderwagonAddPoint*(dst: var EC_P, src: EC_P) =
  dst.sum(dst, src)


proc bandesnatchSubtract*(x, y: Fr[Banderwagon]): Fr[Banderwagon] =
  result.diff(x, y)


# SetUint64 z = v, sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
proc bandesnatchSetUint64*(z: var Fr[Banderwagon], v: uint64) =
  z.fromInt(int(v))


proc fromLEBytes*(field: var Fr[Banderwagon], data: openArray[byte]) =
  var temp{.noinit.}: matchingOrderBigInt(Banderwagon)
  temp.unmarshal(data, littleEndian)
  field.fromBig(temp)
  

func serializePoint*(point: EC_P): Bytes32 =
  assert result.serialize(point) == CttCodecEccStatus.cttCodecEcc_Success
