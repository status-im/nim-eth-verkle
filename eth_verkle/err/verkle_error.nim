#   Nimbus
#   Copyright (c) 2021-2023 Status Research & Development GmbH
#   Licensed and distributed under either of
#     * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#     * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
#   at your option. This file may not be copied, modified, or distributed except according to those terms.

#########################################################################
#
#                   ExtensionStatus Enum in Verkle
#
#########################################################################

type 
  ExtensionStatus* = enum
    # Missing the child node along with the path
    extStatusAbsentEmpty,
    # Path led a node with a different stem entirely
    extStatusAbsentOther,
    # Stem Present
    extStatusPresent

#########################################################################
#
#                   Verkle Error Enums in Verkle
#
#########################################################################

type
  InsertIntoHashError = object of ValueError
  DeleteHashError = object of ValueError
  ReadFromInvalidError = object of ValueError
  SerializeHashedNodeError = object of ValueError
  InsertIntoOtherStemError = object of ValueError
  UnknownNodeTypeError = object of ValueError
  MissingNodeInStatelessError = object of ValueError
  IsPOAStubError = object of ValueError