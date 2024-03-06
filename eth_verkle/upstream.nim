#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

##  This module provides the math primitives used to compute Verkle commitments,
##  obtained from the Constantine library

import
  ../constantine/constantine/ethereum_verkle_trees,
  ../constantine/constantine/math/arithmetic,
  ../constantine/constantine/math/config/curves,
  ../constantine/constantine/math/io/[io_bigints, io_fields]

type
  Bytes32* = Bytes
    ## A 32-bytes blob that can represent a verkle key or value
  Field* = Fr[Banderwagon]
  Point* = EC_P

export
  ethereum_verkle_trees