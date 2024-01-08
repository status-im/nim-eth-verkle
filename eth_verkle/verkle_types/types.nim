import
  ../../constantine/constantine/platforms/primitives,
  ../../constantine/constantine/math/config/[type_ff, curves],
  ../../constantine/constantine/math/elliptic/ec_twistededwards_projective,
  ../../constantine/constantine/math/arithmetic,
  ../../constantine/constantine/math/io/io_fields,
  ../../constantine/constantine/curves_primitives

const 
  DOMAIN*: int = 256
  seed* = asBytes"eth_verkle_oct_2021"
  generator* = Banderwagon.getGenerator()

type
  Bytes* = array[32, byte]
  EC_P* = ECP_TwEdwards_Prj[Fp[Banderwagon]]
  EC_P_Fr* = Fr[Banderwagon]

  IPAProof* = object
    L_vector*: array[8,EC_P]
    R_vector*: array[8,EC_P]
    A_scalar*: EC_P_Fr

  MultiProof* = object
    IPAprv*: IPAProof
    D*: EC_P

  PrecomputedWeights* = object
    barycentricWeights*: array[512,EC_P_Fr]
    invertedDomain*: array[510,EC_P_Fr]

  IPASettings* = object
    SRS*: array[DOMAIN,EC_P]
    Q_val*: EC_P
    precompWeights*: PrecomputedWeights
    numRounds*: uint64

  Coord* = object 
    x*: EC_P_Fr
    y*: EC_P_Fr


