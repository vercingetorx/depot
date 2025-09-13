# Common types used across Dilithium modules.

import params

type
  Poly* = object
    coeffs*: array[N, int32]

  Polyvecl* = object
    vec*: array[L, Poly]

  Polyveck* = object
    vec*: array[K, Poly]

  MatrixA* = array[K, Polyvecl]   # A is K×L (row i is Polyvecl)
