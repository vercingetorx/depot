# Common helpers for slicing without copying.

template oa*[T](b: var openArray[T]; off, count: int): untyped =
  ## Mutable window as openArray.
  doAssert off >= 0 and count >= 0 and off + count <= b.len
  toOpenArray(b, off, off + count - 1)

template roa*[T](b: openArray[T]; off, count: int): untyped =
  ## Read-only window as openArray.
  doAssert off >= 0 and count >= 0 and off + count <= b.len
  toOpenArray(b, off, off + count - 1)
