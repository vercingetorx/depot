import params

type
  Poly* = object
    coeffs*: array[KYBER_N, int16]
