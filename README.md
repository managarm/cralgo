# Managarm's Library of Freestanding Cryptographic Algoriths

This library implements freestanding versions of various cryptographic
primitives. As of now, AES256 and SHA256 are implemented.

We do not aim to provide original implementations the afforementioned primitives
as implementing cryptographic algorithms is non-trivial (e.g., to defend against
sidechannel attacks) and requires great care and frequent maintainance.
Instead, we borrow our implementations from the
excellent [Botan](https://botan.randombit.net/) library and adopt them to be
freestanding. As far as possible, the original source code is kept intact such
that merging improvements and fixes from upstream remains possible.

Note that since this library is freestanding, it is less intuitive to use
than a general-purpose library (such as Botan) and requires even more care.
Compared to Botan, notable differences in the security model include:

* Users need to ensure that secrets do not leak into swap files and/or
  core dumps. Users are responsible for putting secret keys and other
  state into non-swapable memory.

All non-trivial changes compared to Botan are annotated by `[cralgo]` comments
in the source. Other, more trivial changes include:

* The compiler is assumed to be GCC or GCC-compatible (e.g., Clang).
* Botan-specific macros are replaced by generic macros. For example,
  `BOTAN_ASSERT` is replaced by `assert` and
  `BOTAN_TARGET_CPU_HAS_NATIVE_64BIT` is replaced by `__LP64__`.
* Annotations for sanitizers such as `CT::{poison,unpoison}` are removed.

This library uses code from Botan. The latter is developed by Jack Lloyd
and contributors and is available under a 2-clause BSD license
(just like this project), see LICENSE.
