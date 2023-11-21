---
title: "The Belt, Bign and Bake families of cryptographic algorithms
  and protocols"
abbrev: "belt-bign-bake"
docname: draft-belt-bign-bake-latest
submissiontype: independent
category: info

ipr: trust200902
keyword:
  - Internet-Draft
  - belt
  - bign
  - bake

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Sergey Agievich
    ins: S. Agievich
    organization: APMI, Belarusian State University
    email: agievichi@bsu.by
 -
    name: Nikolai Kalosha
    ins: N. Kalosha
    organization: IM, Academy of Sciences of Belarus
    email: kalosha@im.bas-net.by

contributor:
  -
    name: Nastassia Kozlovskaya
    ins: N. Kozlovskaya
    organization: APMI, Belarusian State University

normative:

  RFC9180:
    title: "Hybrid Public Key Encryption"
    rc: "Internet Research Task Force (IRTF), Request for Comments: 9180, 2022"
    target: https://www.rfc-editor.org/info/rfc9180
    author:
      -
        ins: R. Barnes
        name: Richard Barnes
      -
        ins: K. Bhargavan
        name: Karthikeyan Bhargavan
      -
        ins: B. Lipp
        name: Benjamin Lipp
      -
        ins: C. Wood
        name: Christopher A. Wood

informative:

  ExpS:
    title: "Exponential S-boxes (In Russian)"
    rc: "Vesti NAN Belarusi, 2005(1), pp. 106-112"
    target: https://eprint.iacr.org/2004/024
    author:
      -
        ins: S. Agievich
        name: Sergey Agievich
        org: Belarusian State University
      -
        ins: A. Afonenko
        name: Andrey Afonenko
        org: Belarusian State University

  CCITT.X208:
    title: "International Telephone and Telegraph Consultative Committee.
    Specification of Abstract Syntax Notation One (ASN.1)"
    rc: "CCITT Recommendation X.208, November 1988"

  XS:
    title: "XS-circuits in block ciphers"
    rc: "Mat. Vopr. Kriptogr., 10(2), 2019, 7-30"
    target: https://eprint.iacr.org/2018/592
    author:
      -
        ins: S. Agievich
        name: Sergey Agievich
        org: Belarusian State University

  CTR2AE:
    title: "The Counter mode with encrypted nonces and its extension to AE"
    rc: "Mat. vopr. kriptogr., 11(2), 2020, 7-24"
    target: https://eprint.iacr.org/2020/331
    author:
      -
        ins: S. Agievich
        name: Sergey Agievich
        org: Belarusian State University

  BFK09:
    title: "Security Analysis of the PACE Key-Agreement Protocol"
    rc: "Cryptology ePrint Archive, Report 2009/624, 2009"
    author:
      -
        ins: J. Bender
        name: Jens Bender
      -
        ins: M. Fischlin
        name: Marc Fischlin
      -
        ins: D. Kuegler
        name: Dennis Kuegler

  BCIMRT10:
    title: "Efficient Indifferentiable Hashing into Ordinary Elliptic Curves"
    rc: "Rabin T. (eds) Advances in Cryptology -– CRYPTO 2010, Lecture Notes in
      Computer Science, 6223, 237--254, Berlin, Heildeberg: Springer, 2010"
    author:
      -
        ins: E. Brier
        name: Eric Brier
      -
        ins: J. Coron
        name: Jean-Sebastien Coron
      -
        ins: T. Icart
        name: Thomas Icart
      -
        ins: D. Madore
        name: David Madore
      -
        ins: H. Randriam
        name: Hugues Randriam
      -
        ins: M. Tibouchi
        name: Mehdi Tibouchi

  Che10:
    title: "Discrete Logarithm Problems with Auxiliary Inputs"
    rc: "J. Cryptology, 23, 2010, 457–476"
    author:
      -
        ins: J.H. Cheon
        name: Jung Hee Cheon

  DOW92:
    title: "Authentication and Authenticated Key Exchanges"
    rc: "Designs, Codes and Cryptography, 2(2), 1992, 107-125"
    author:
      -
        ins: W. Diffie
        name: Whitfield Diffie
      -
        ins: P. Oorschot
        name: Paul C. Van Oorschot
      -
        ins: M. Wiener
        name: Michael J. Wiener

  GOST:
    title: "GOST 28147-89. Cryptographic Protection for Information Processing Systems"
    rc: "Government Standard of the USSR. In Russian. Moscow: Government
      Committee of the USSR for Standards, 1989"

  HMV04:
    title: "Guide to Elliptic Curve Cryptography"
    rc: "New York: Springer, 2004"
    author:
      -
        ins: D. Hankerson
        name: Darrel Hankerson
      -
        ins: A. Menezes
        name: Alfred Menezes
      -
        ins: S. Vanstone
        name: Scott Vanstone

  OMAC:
    title: "OMAC: One-Key CBC MAC"
    rc: "Johansson T. (eds) Fast Software Encryption, FSE 2003, Lecture Notes in Computer Science, 2887, 129-153, Berlin, Heildeberg: Springer, 2003"
    author:
      -
        ins: T. Iwata
        name: Tetsu Iwata
      -
        ins: K. Kurosawa
        name: Kaoru Kurosawa

  LMQSV03:
    title: "An Efficient Protocol for Authenticated Key Agreement"
    rc: "Designs, Codes and Cryptography, 28(2), 2003, 119-134"
    author:
      -
        ins: L. Law
        name: Laurie Law
      -
        ins: A. Menezes
        name: Alfred Menezes
      -
        ins: M. Qu
        name: Minghua Qu
      -
        ins: J. Solinas
        name: Jerry Solinas
      -
        ins: S. Vanstone
        name: Scott Vanstone

  LidNie97:
    title: "Finite Fileds"
    rc: "Cambridge University Press, 1997"
    author:
      -
        ins: R. Lidl
        name: Rudolf Lidl
      -
        ins: H. Niederreiter
        name: Harald Niederreiter

  GCM:
    title: "The security and performance of the Galois/Counter Mode (GCM)
      of operation"
    rc: "Canteaut A. and Viswanathan K. (eds) Progress in Cryptology --
      INDOCRYPT 2004, Lecture Notes in Computer Science, 3348, 343-355, Berlin,
      Heidelberg: Springer, 2005"
    author:
      -
        ins: D.A. McGrew
        name: David McGrew
      -
        ins: J. Viega
        name: John Viega

  Rog02:
    title: "Authenticated-encryption with associated-data"
    rc: "CCS'02: Proceedings of the 9th ACM conference on Computer and
      communications security, 2002, 98-107"
    author:
      -
        ins: P. Rogaway
        name: Phillip Rogaway

  Sch91:
    title: "Efficient Signature Generation by Smart Cards"
    rc: "J. Cryptology, 4(3), 1991, 161-174"
    author:
      -
        ins: C.P. Schnorr
        name: Claus P. Schnorr

--- abstract

This document describes the Belt, Bign and Bake families of cryptographic
algorithms and protocols standardized in Belarus. These families cover
symmetric encryption and authentication, hashing, digital signature, key
transport (public key encryption of symmetric keys), authenticated key
establishment.

--- middle

# Introduction

This document describes the Belt, Bign and Bake families of cryptographic
algorithms and protocols standardized in Belarus as STB 34.101.31,
STB 34.101.45, STB 34.101.66. Here STB stands for "STandard of Belarus".

STB 34.101.31 (Belt) covers symmetric encryption and data authentication,
hashing and key management. There are three version of the standard dated 2007,
2011 and 2020. Disk encryption and format-preserving encryption algorithms
introduced in the last (current) version are omitted in this specification.

Originally, Belt was the name of a 128-bit block cipher developed in 2001 and
standardized 6 years later. The name was adopted for the whole STB 34.101.31
standard, and the underlying block cipher is now referred to as `belt-block`.

STB 34.101.45 (Bign) covers digital signatures and key transport (meaning
public key encryption of symmetric keys) based on elliptic curves. There are
two version of the standard dated 2011 and 2013.

STB 34.101.66 (Bake) covers key establishment protocols based on elliptic
curves. The standard was released in 2014, and it had no revisions. The name
"Bake" originates from an acronym for "authenticated key establishment".

Algorithms and protocols of the Belt, Bign and Bake families are defined in
{{BELT}}, {{BIGN}} and {{BAKE}} respectively. {{NOTATION}} presents the
necessary notation and conventions.

Elliptic curves that are recommended to use with the Bign and Bake families are
listed in Appendix {{CURVES}}. ASN.1 {{CCITT.X208}} object identifiers and data
types are defined in {{ASN1}}. Standardized ASN.1 definitions allow for improved
reliability and interoperability of independent implementations of the
standards.

# Notation {#NOTATION}

## General

`NULL` :
: empty input, error;

`!=` :
: not equal;

`a^b`, `a^{b}` :
: `b` is the upper index of `a`;

`a_b`, `a_{b}` :
: `b` is the lower index of `a`;

`a b`, `a * b` :
: multiplication;

`{a, b, c, ...}` :
: the set of elements `a, b, c, ...`;

`a in S` :
: `a` belongs to `S`;

`alg(u_1, u_2, ...)` :
: call the algorithm `alg` with inputs `u_1, u_2, ...`;

`a <- u` :
: assign `u` to `a`;

`a <- S` :
: for a set `S`, the same as `a <- u`, where `u` chosen uniformly at
  random from `S`;

`(a_1, a_2, ...) <- (u_1, u_2, ...)` :
: the same as `a_1 <- u_1`, `a_2 <- u_2, ...`;

`(NULL, a_2) <- (u_1, u_2)` :
: the same as `a_2 <- u_2` (`u_1` is ignored);

`a <-> b` :
: swap the values of `a` and `b`.

## Words and integers

`{0, 1}^*` :
: the set of all words of finite lengths in the alphabet `{0, 1}`
  (including the empty word of length 0);

`|u|` :
: the length of `u in {0, 1}^*`;

`{0, 1}^n` :
: the set of all words of length n in the alphabet `{0, 1}`;

`{0, 1}^n*` :
: the set of all words of lengths divisible by `n` in the alphabet `{0, 1}`;

`Lo(u, m)` :
: for `u in {0, 1}^n` and `m <= n`, the word `u` truncated to the first `m`
  symbols;

`Hi(u, m)` :
: for `u in {0, 1}^n` and `m <= n`, the word `u` truncated to the last `m`
  symbols;

`u || v` :
: for `u, v in {0, 1}^*`, the concatenation of the words `u` and `v`,
  i.e., the word `w` of length `|u| + |v|` such that `Lo(w, |u|) = u` and
  `Hi(w, |v|) = v`;

`Rep(u, m)` :
: for `u in {0, 1}^*` and a positive integer `m`, the concatenation of `m`
  copies of `u`;

`Split(u, m)` :
: for `u in {0, 1}^*` and a positive integer `m` :

  - the empty tuple `()` if `|u| = 0`;
  - the one element tuple `(u)` if `0 < |u| <= m`;
  - the tuple `(Lo(u, m), Split(Hi(u, |u| - m), m))` if `|u| > m`;

`U mod m` :
: for an integer `U` and a positive integer `m`, the remainder of the division
  of `U` by `m`;

`u ^ v` :
: for `u = u_1 u_2 ... u_n` and `v = v_1 v_2 ... v_n in {0, 1}^n`,
  the word `w = w_1 w_2 .... w_n` such that `w_i = (u_i + v_i) mod 2`
  (bitwise exclusive or);

`[u]` :
: for `u in {0, 1}^8*`, the number:

  - `0`, if `|u| = 0`;
  - `128 u_1 + 64 u_2 + ... + u_8`, if `|u| = 8`, `u = u_1 u_2 ... u_8`;
  - `[Lo(u, 8)] + 256 [Hi(u, |u| - 8)]`, if `|u| > 8`
    (binary word to number conversion);

`<U>_{8*n}` :
: for a non-negative integer `U` and a positive integer `n`,
  the word `u in {0, 1}^{8n}` such that `[u] = U mod 2^{8*n}`;

`u + v` :
: for `u, v in {0, 1}^{8*n}`, the word `<[u] + [v]>_{8*n}`;

`u - v` :
: for `u, v in {0, 1}^{8*n}`, the word `w in {0, 1}^{8*n}` such that
  `u = w + v`;

`ShLo(u, r)` :
: for `u in {0, 1}^{8*n}` and a positive integer `r < 8*n`,
  the word `<[u] / 2^r>_{8*n}`, where the quotient is truncated to the
  nearest integer from below;

`ShHi(u, r)` :
: for `u in {0, 1}^{8*n}` and a positive integer `r < 8*n`, the word
  `<2^r [u]>_{8n}`;

`RotHi(u, r)` :
: for `u in {0, 1}^{8*n}`, the word `ShHi(u, r) ^ ShLo(u, 8*n - r)`.

## Protocols

`A, B` :
: parties of a protocol;

`o_A, o_B` :
: an object `o` belongs to (originates from) `A` or `B`;

`Cert(Id, Q)` :
: a public key certificate that binds an identifier `Id` of a party with
  its public key `Q`;

`[[ text ]]` :
: an optional message (action) of the protocol;

`{{ text }}` :
: a mandatory message (action) of the protocol that can be transmitted
  (executed) in advance (before the protocol execution) or implicitly;

`hello` :
: a service message that is used to initialize a protocol, a predefined
  word in `{0, 1}^*`.

## Miscellaneous

`--` :
: dash;

`\` :
: no line break; used to split large sequences of digits into lines for
  convenience;

`0x` :
: prefix followed by a hexadecimal representation of `u in {0, 1}^{4*}`:

  - every four consecutive bits of `u` are represented by a hexadecimal
    digit in `{0, 1, ..., 9, A, B, C, D, E, F}` (e.g., `10110001 = 0xB1`);

`OID(o)` :
: an identifier of an object `o`, a word in `{0, 1}^{8*}`.

## Conventions

for `i = 1, 2, ..., m` :

  - the body of the loop is executed `m` times for `m > 1`;
  - the body of the loop is executed once for `m = 1`;
  - the body of the loop is never executed for `m < 1`;

`(a_1, a_2, ..., a_m)`:

  - a tuple of `m` elements for `m > 1`;
  - a tuple of one element `a_1` for `m = 1`;
  - an empty tuple for `m < 1`.

# Belt algorithms {#BELT}

## Preliminaries

Belt is a family of cryptographic algorithms that implement conventional
mechanisms of symmetric cryptography: encryption, data authentication,
authenticated encryption, hashing. Their purpose is to provide data
confidentiality and to control data integrity and authenticity. The processed
data are binary words (messages).

The algorithms in the Belt family are based on three primitives:

* `belt-block` -- block encryption;
* `belt-wblock` -- wide block encryption;
* `belt-compress` -- cryptographic compression.

Block encryption is the lowest level primitive, the `belt-wblock` and
`belt-compress` algorithms are built on top of it. Hereinafter a block is
defined as a binary word of length 128.

Baseline Belt algorithms are the following:

* `belt-ecb` -- encryption in the ECB (Electronic CodeBook) mode;
* `belt-cbc` -- encryption in the CBC (Cipher Block Chaining) mode;
* `belt-cfb` -- encryption in the CFB (Cipher FeedBack) mode;
* `belt-ctr` -- encryption in the CTR (CounTeR) mode;
* `belt-mac` -- data authentication through MAC (Message Authentication Codes);
* `belt-dwp` -- authenticated encryption with associated data (AEAD, {{Rog02}})
  in the DWP (DataWraP) mode;
* `belt-che` -- AEAD in the CHE (Counter-Hash-Encrypt) mode;
* `belt-kwp` -- wrapping (authenticated encryption of) keys;
* `belt-hash` -- hashing.

Baseline Belt algorithms are supported by the following key management algorithms:

* `belt-keyexpand` -- expansion of keys to the standard length;
* `belt-keyrep` -- key derivation.

Each encryption algorithm is accompanied by a decryption counterpart whose
name is suffixed with "`-inv`". The same holds for AEAD and key wrapping
algorithms.

The encryption modes are implemented in a conventional manner, with the
following particular features:

* the `belt-ecb` and `belt-cbc` implementations rely on CTS (CipherText Stealing)
  technique to allow for messages with a non-integral number of blocks;
* the `belt-ctr` implementation encrypts the nonce (the initialization vector)
  before using it to to generate a sequence of counters.

Thus, `belt-ctr` implements the CTR2 mode introduced in GOST 28147-89 {{GOST}},
as opposed to the classical CTR mode.

The `belt-mac` algorithm implements the OMAC mode {{OMAC}}. Unlike the standard
approach, this implementation does not require multiplication in the field of
`2^128` elements.

In the `belt-dwp` and `belt-che` algorithms, the DWP and CHE modes of AEAD described
in {{CTR2AE}} are implemented. The data wrapping algorithm `belt-dwp` retains logic
from `belt-ctr`, which enables calculation of `belt-ctr-compatible` authentication
tags for the encrypted data and the associated (optional public) data. The DWP
mode is similar to the well-known GCM mode {{GCM}}, but has better security
properties under nonce misuse (repeated nonce).

The CHE (counter-hash-encrypt) mode offers slightly reduced complexity
compared to DWP by reducing the number of calls to `belt-block` by one.
However, the generated authentication tag is no longer compatible with
`belt-ctr`.

The DWP and CHE modes can produce authentication tags for partial data, which
facilitates processing of large data streams.

The `belt-kwp` algorithm wraps a key, i.e., a binary word of arbitrary length
greater than 128, by appending it with a 128-bit header and encrypting it with
belt-wblock. The unwrapping algorithm `belt-kwp-inv` performs `belt-wblock-inv`
decryption and compares the resulting header to the header it received as an
input. This facilitates both confidentiality and authenticity control of
cryptographic keys.

The basic `belt-wblock` algorithm has its own significance. It can be used to
encrypt a wide data block (for example, 4 KBytes long) in such a way that
every byte of the plaintext has an effect on all bytes of the ciphertext. The
design of `belt-wblock` relies on the theory of XS-circuits {{XS}}.

The `belt-compress` algorithm performs one-way compression of 512-bit words to
256 bits and calculates a 64-bit counter.

The `belt-hash` algorithm implements hashing from `belt-compress`. To process
two 128-bit blocks of data, `belt-compress` invokes `belt-block` 3 times, i.e.,
the hash rate is approximately 2/3 of the encryption rate.

The `belt-keyrep` algorithm provides a lightweight key derivation function. The
algorithm can be used for key renewal and key diversification (generating a
family of secret keys from a master key and some unique inputs). The
`belt-keyrep` algorithm is based on `belt-compress`. Like `belt-compress`, it
invokes `belt-block` 3 times.

## Objects {#BELT.Objects}

The cryptographic keys used by the Belt family are binary words of length 256.
Keys must be generated using random number generators or pseudorandom number
generators with secret parameters of sufficient length (entropy).

Keys of lengths 128 and 192 can be used to derive 256-bit keys by applying the
`belt-keyexpand` algorithm.

The same key must not be used in different algorithms except for the cases when
these algorithms are pairwise inverse, that is, their names differ only by the
"`-inv`" suffix.

Data encryption keys must be applied according to the quotas defined in
{{QUOTAS}}.

In the `belt-cbc`, `belt-cfb`, `belt-ctr`, `belt-dwp`, and `belt-che`
algorithms, a nonce `S in {0, 1}^128`, also known as an initialization vector, is used.
Nonces are not kept confidential, they are usually transmitted along with
the respective ciphertext.

The `belt-cfb`, `belt-ctr`, `belt-dwp`, and `belt-che` algorithms imply the use of
unique nonces. This means that nonces that are used with the same key collide
with only a negligible probability. In the `belt-cbc` algorithm, a nonce must not
only be unique, but also unpredictable. Unpredictability means a negligible
probability of guessing the nonce for the next invocation of the algorithm.

The `belt-mac`, `belt-dwp`, and `belt-che` algorithms calculate authentication
tags `T in {0, 1}^64`. These tags, also known as message authentication codes,
serve as key-dependent cryptographic checksums. To generate a tag of size
`n < 64` bits, truncation to the first n bits is applied.

The `belt-hash` algorithm calculates hash values `H in {0, 1}^256`. Hash values
serve as `key-independent` cryptographic checksums. To generate a hash value
of size `n < 256`, truncation to the first n bits is applied.

In the `belt-kwp` and `belt-keyrep` algorithms, keys are accompanied by headers
`I in {0, 1}^128`. A header can contain public information about the associated
key: type, owner and series identifiers, validity period, etc. By default, the
128-bit zero word `Rep(0, 128)` is used as a header.

In the `belt-keyrep` algorithm, a depth `D in {0, 1}^96` is used as an input in
addition to a header `I`. A key of depth D is used to derive a subordinate key:
the key of depth `D` is used as the source key, depth is incremented by `1`
(`D +<1>_{96}`), and the header is changed if needed. By default, `D` is the
zero word `Rep(0, 96)`.

## Blocks as binary polynomials

In the `belt-dwp` and `belt-che` algorithms, blocks are interpreted as
polynomials of degree 127 (or less) over the binary field `{0, 1}`.
The polynomials are added and multiplied modulo a fixed irreducible
polynomial of degree 128. Thus, operations on polynomials are performed
in a finite field (Galois field, see {{LidNie97}}) of size `2^128`.

The transition from blocks to polynomials and the field operations are
formally defined as follows.

 `u(x)`:
: for `a` word `u in {0, 1}^8*`, the polynomial:

  - `0`, if `|u| = 0`;
  - `u_1 x^7 + u_2 x^6 + ... + u_8`, if `|u| = 8, u = u1 u_2 ... u_8`;
  - `Lo(u, 8)(x) + x^8 Hi(u, |u| - 8)(x)`, if `|u| > 8`;

 `u(x) mod f(x)`:
: for a polynomial `u(x)` and a nonzero polynomial `f(x)`,
  the remainder of the division of `u(x)` by `f(x)`;

 `u * v`:
: for words `u`, `v in {0, 1}^128`, the word `w in {0, 1}^128` such
  that `w(x) = u(x)v(x) mod f(x)`, where `f(x) = x^128 + x^7 + x^2 + x + 1`.

## S-box `H`

The S-box `H` transforms `x in {0, 1}^8` as follows.

1. Parse `(x_1, x_2) = Split(x, 4)`.
2. Find the octet `y` lying in row `x_1` and column `x_2` of {{SBOX}}
   (all data in the table are the hexadecimal notation).
3. Return `y`.

|  |0  |1  |2  |3  |4  |5  |6  |7  |8  |9  |A  |B  |C  |D  |E  |F  |
|--|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|0 |B1 |94 |BA |C8 |0A |08 |F5 |3B |36 |6D |00 |8E |58 |4A |5D |E4 |
|1 |85 |04 |FA |9D |1B |B6 |C7 |AC |25 |2E |72 |C2 |02 |FD |CE |0D |
|2 |5B |E3 |D6 |12 |17 |B9 |61 |81 |FE |67 |86 |AD |71 |6B |89 |0B |
|3 |5C |B0 |C0 |FF |33 |C3 |56 |B8 |35 |C4 |05 |AE |D8 |E0 |7F |99 |
|4 |E1 |2B |DC |1A |E2 |82 |57 |EC |70 |3F |CC |F0 |95 |EE |8D |F1 |
|5 |C1 |AB |76 |38 |9F |E6 |78 |CA |F7 |C6 |F8 |60 |D5 |BB |9C |4F |
|6 |F3 |3C |65 |7B |63 |7C |30 |6A |DD |4E |A7 |79 |9E |B2 |3D |31 |
|7 |3E |98 |B5 |6E |27 |D3 |BC |CF |59 |1E |18 |1F |4C |5A |B7 |93 |
|8 |E9 |DE |E7 |2C |8F |0C |0F |A6 |2D |DB |49 |F4 |6F |73 |96 |47 |
|9 |06 |07 |53 |16 |ED |24 |7A |37 |39 |CB |A3 |83 |03 |A9 |8B |F6 |
|A |92 |BD |9B |1C |E5 |D1 |41 |01 |54 |45 |FB |C9 |5E |4D |0E |F2 |
|B |68 |20 |80 |AA |22 |7D |64 |2F |26 |87 |F9 |34 |90 |40 |55 |11 |
|C |BE |32 |97 |13 |43 |FC |9A |48 |A0 |2A |88 |5F |19 |4B |09 |A1 |
|D |7E |CD |A4 |D0 |15 |44 |AF |8C |A5 |84 |50 |BF |66 |D2 |E8 |8A |
|E |A2 |D7 |46 |52 |42 |A8 |DF |B3 |69 |74 |C5 |51 |EB |23 |29 |21 |
|F |D4 |EF |D9 |B4 |3A |62 |28 |75 |91 |14 |10 |EA |77 |6C |DA |1D |
{: #SBOX title="The S-box `H`"}

Remark. `H` is constructed using exponentiation in a field of `2^8` elements
following {{ExpS}}. The direct algorithm for generating `H` is provided in
{{BELTH}}.

## Constants `BeltH`

The S-Box `H` defines a family of constants `BeltH`. The family is
parameterized by non-negative integers `u` и `n` such that `a + n <= 256`.

A particular constant `BeltH(u, n)` is defined as
`H(<u>_8) || H(<u + 1>_8) || .... || H(<u + n - 1>_8)`.

For example, `BeltH(79, 3) = 0xF1C1AB` (`<79>_8 = 0x4F`).

## Block encryption

Block encryption is defined by the encryption algorithm `belt-block` and the
decryption algorithm `belt-block-inv`. These algorithms use auxiliary
transformations `G_5`, `G_13`, `G_21` which, in turn, use an S-box `H`.

### The transformations `G_r`

The transformations `G_5`, `G_13`, `G_21` map the set `{0, 1}^32` to itself.
They are derived from an algorithm `G` by taking `G_r(x) = G(x, r)`.

The algorithm `G` is defined as follows.

Input:

* `x in {0, 1}^32`;
* `r in {5, 13, 21}`.

Output:

* `y in {0, 1}^32`.

Steps:

1. Parse `(x_1, x_2, x_3, x_4) = Split(x, 8)`.
2. `y <- RotHi(H(x_1) || H(x_2) || H(x_3) || H(x_4), r)`.
3. Return `y`.

### Block encryption: the `belt-block` algorithm

Input:

* `X in {0, 1}^128` -- a plaintext block;
* `K in {0, 1}^256` -- a key.

Output:

* `Y in {0, 1}^128` -- the encrypted block.

Steps:

1. `(a, b, c, d) <- Split(X, 32)`.
2. `(k[1], k[2], ..., k[56]) <- Split(Rep(K, 7), 32)`.
3. For `i = 1, 2, ..., 8`:
   1.  `b <- b ^ G_5(a + k[7i-6], 5)`;
   2.  `c <- c ^ G_21(d + k[7i-5], 21)`;
   3.  `a <- a - G_13(b + k[7i-4], 13)`;
   4.  `e <- G_21(b + c + k[7i-3], 21) ^ <i>_32`;
   5.  `b <- b + e`;
   6.  `c <- c - e`;
   7.  `d <- d + G_13(c + k[7i-2], 13)`;
   8.  `b <- b ^ G_21(a + k[7i-1], 21)`;
   9.  `c <- c ^ G_5(d + k[7i], 5)`;
   10. `a <-> b`;
   11. `c <-> d`;
   12. `b <-> c`.
4. `Y <- b || d || a || c`.
5. Return `Y`.

### Block decryption: the `belt-block-inv` algorithm

Input:

* `Y in {0, 1}^128` -- a ciphertext block;
* `K in {0, 1}^256` -- a key.

Output:

* `X in {0, 1}^128` -- the decrypted block.

Steps:

1. `(a, b, c, d) <- Split(Y, 32)`.
2. `(k[1], k[2], ..., k[56]) <- Split(Rep(K, 7), 32)`.
3. For `i = 8, ..., 2, 1`:
   1.  `b <- b ^ G_5(a + k[7i], 5)`;
   2.  `c <- c ^ G_21(d + k[7i-1], 21)`;
   3.  `a <- a - G_13(b + k[7i-2], 13)`;
   4.  `e <- G_21(b + c + k[7i-3], 21) ^ <i>_32`;
   5.  `b <- b + e`;
   6.  `c <- c - e`;
   7.  `d <- d + G_13(c + k[7i-4], 13)`;
   8.  `b <- b ^ G_21(a + k[7i-5], 21)`;
   9.  `c <- c ^ G_5(d + k[7i-6], 5)`;
   10. `a <-> b`;
   11. `c <-> d`;
   12. `a <-> d`.
4. `Y <- c || a || d || b`.
5. Return `Y`.

## Wide-block encryption

Wide-block encryption is defined by the encryption algorithm `belt-wblock` and
the decryption algorithm `belt-wblock-inv`.

### Wide-block encryption: the `belt-wblock` algorithm

Input:

* `X in {0, 1}^8*` -- a plaintext wide block, `|X| >= 256`;
* `K in {0, 1}^256` -- a key.

Output:

* `Y in {0, 1}^|X|` -- the encrypted block.

Steps:

1. `r <- X`.
2. Represent `r` in two ways:
   - as the tuple `(r_1, r_2, ..., r_n) = Split(r, 128)`;
   - `r = r** || r*, where |r*| = 128`.
3. For `i = 1, 2, ..., 2n`:
   1. `s <- r_1 ^ r_2 ^ ... ^ r_{n-1}`;
   2. `r* <- r* ^ belt-block(s, K) ^ <i>_128`;
   3. `r <- ShLo(r, 128)`;
   4. `r* <- s`.
4. `Y <- r`.
5. Return `Y`.

### Wide-block decryption: the `belt-wblock-inv` algorithm

Input:

* `Y in {0, 1}^8*` -- a ciphertext wide block, `|Y| >= 256`;
* `K in {0, 1}^256` -- a key.

Output:

* `X in {0, 1}^|Y|` -- the decrypted wide block.

Steps:

1. `r <- Y`.
2. Represent `r` in two ways:
   * as the tuple `(r_1, r_2, ..., r_n) = Split(r, 128)`;
   * `r = r** || r*`, where `|r*| = 128`.
3. For `i = 2n, ..., 2, 1`:
   1. `s <- r*`;
   2. `r <- ShHi(r, 128)`;
   3. `r* <- r* ^ belt-block(s, K) ^ <i>_128`;
   4. `r <- ShLo(r, 128)`;
   5. `r_1 <- s ^ r_2 ^ ... ^ r_{n-1}`.
4. `X <- r`.
5. Return `X`.

## One-way compression

One-way compression is defined by the `belt-compress` algorithm.

Input:

* `X in {0, 1}^512`.

Output:

* `S in {0, 1}^64`;
* `Y in {0, 1}^256`.

Steps:

1. Parse `(X_1, X_2, X_3, X_4) = Split(X, 128)`.
2. `S <- belt-block(X_3 ^ X_4, X_1 ^ X_2) ^ X_3 ^ X_4`.
3. `Y_1 <- belt-block(X_1, S || X_4) ^ X_1`.
4. `Y_2 <- belt-block(X_2, (S ^ Rep(1, 128)) || X_3) ^ X_2`.
5. Return `(S, Y)`, where `Y = Y_1 || Y_2`.

## Encryption in the ECB mode

Encryption in the ECB mode is defined by the encryption algorithm `belt-ecb`
and the decryption algorithm `belt-ecb-inv`.

### ECB encryption: the `belt-ecb` algorithm

Input:

* `X in {0, 1}^*` -- plaintext data, `|X| >= 128`;
* `K in {0, 1}^256` -- a key.

Output:

* `Y in {0, 1}^|X|` -- the encrypted data.

Steps:

1. Parse `(X_1, X_2, ..., X_n) = Split(X, 128)`.
2. If `|X_n| = 128`, then
   1. for `i = 1, 2, ..., n do`:
      1. `Y_i <- belt-block(X_i, K)`.
3. Else, if `|X_n| < 128`, then
   1. for `i = 1, 2, ..., n - 2` do:
      1. `Y_i <- belt-block(X_i, K)`;
   2. `(Y_n || r) <- belt-block(X_{n-1}, K)`, where `|Y_n| = |X_n|`;
   3. `Y_{n-1} <- belt-block(X_n || r, K)`.
4. Return `Y = Y_1 || Y_2 || ... || Y_n`.

### ECB decryption: the `belt-ecb-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data, `|Y| >= 128`;
* `K in {0, 1}^256` -- a key.

Output:

* `X in {0, 1}^|Y|` -- the decrypted data.

Steps:

1. Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2. If `|Y_n| = 128`, then:
   1. for `i = 1, 2, ..., n` do:
      2. `X_i <- belt-block-inv(Y_i, K)`.
3. Else, if `|X_n| < 128`, then:
   1. for `i = 1, 2, ..., n - 2` do:
      2. `X_i <- belt-block-inv(Y_i, K)`;
   2. `(X_n || r) <- belt-block-inv(Y_{n-1}, K)`, where `|X_n| = |Y_n|`;
   3. `X_{n-1} <- belt-block-inv(Y_n || r, K)`.
4. Return `X = X_1 || X_2 || ... || X_n`.

## Encryption in the CBC mode

Encryption in the CBC mode is defined by the encryption algorithm `belt-cbc` and
the decryption algorithm `belt-cbc-inv`.

### CBC encryption: the `belt-cbc` algorithm

Input:

* `X in {0, 1}^*` -- plaintext data, `|X| >= 128`;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `Y in {0, 1}^|X|` -- the encrypted data.

Steps:

1. Parse `(X_1, X_2, ..., X_n) = Split(X, 128)`.
2. Denote `Y_0 = S`.
3. If `|X_n| = 128`, then
   1. for `i = 1, 2, ..., n` do:
      1. `Y_i <- belt-block(X_i ^ Y_{i-1}, K)`.
4. Else, `if |X_n| < 128`, then
   1. for `i = 1, 2, ..., n - 2` do:
      1. `Y_i <- belt-block(X_i ^ Y_{i-1}, K)`;
   2. `(Y_n || r) <- belt-block(X_{n-1} ^ Y_{n-2}, K)`, where `|Y_n| = |X_n|`;
   3. `Y_{n-1} <- belt-block((X_n ^ Y_n) || r, K)`.
5. Return `Y = Y_1 || Y_2 || ... || Y_n`.

### CBC decryption: the `belt-cbc-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data, `|Y| >= 128`;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `X in {0, 1}^|Y|` -- the decrypted data.

Steps:

1. Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2. Denote `Y_0 = S`.
3. If `|Y_n| = 128`, then:
   1. for `i = 1, 2, ..., n` do:
      1. `X_i <- belt-block-inv(Y_i, K) ^ Y_{i-1}`.
4. Else, if `|X_n| < 128`, then:
   1. for `i = 1, 2, ..., n - 2` do:
      1. `X_i <- belt-block-inv(Y_i, K) ^ Y_{i-1}`;
   2. `(X_n || r) <- belt-block-inv(Y_i, K) ^ Y_{i-1}`, where `|X_n| = |Y_n|`;
   3. `X_{n-1} <- belt-block-inv(Y_n || r, K) ^ Y_{n-2}`.
5. Return `X = X_1 || X_2 || ... || X_n`.

## Encryption in the CFB mode

Encryption in the CFB mode is defined by the encryption algorithm `belt-cfb`
and the decryption algorithm `belt-cfb-inv`.

### CFB encryption: the `belt-cfb` algorithm

Input:

* `X in {0, 1}^*` -- plaintext data;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `Y in {0, 1}^|X|` -- the encrypted data.

Steps:

1. Parse `(X_1, X_2, ..., X_n) = Split(X, 128)`.
2. Denote `Y_0 = S`.
3. For `i = 1, 2, ..., n` do:
   1. `Y_i <- X_i ^ Lo(belt-block(Y_{i-1}, K), |X_i|)`.
4. Return `Y = Y_1 || Y_2 || ... || Y_n`.

### CFB decryption: the `belt-cfb-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `X in {0, 1}^|Y|` -- the decrypted data.

Steps:

1. Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2. Denote `Y_0 = S`.
3. For `i = 1, 2, ..., n` do:
   1. `X_i <- Y_i ^ Lo(belt-block(Y_{i-1}, K), |Y_i|)`.
4. Return `X = X_1 || X_2 || ... || X_n`.

## Encryption in the CTR mode

Encryption in the CTR mode is defined by the encryption algorithm `belt-ctr`
and the decryption algorithm `belt-ctr-inv`.

### CTR encryption: the `belt-ctr` algorithm

Input:

* `X in {0, 1}^*` -- plaintext data;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `Y in {0, 1}^|X|` -- encrypted data.

Steps:

1. Parse `(X_1, X_2, ..., X_n) = Split(X, 128)`.
2. `s <- belt-block(S, K)`.
3. For `i = 1, 2, ..., n` do:
   1. `s <- s + <1>_128`;
   2. `Y_i <- X_i ^ Lo(belt-block(s, K), |X_i|)`.
4. Return `Y = Y_1 || Y_2 || ... || Y_n`.

### CTR decryption: the `belt-ctr-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce.

Output:

* `X in {0, 1}^|Y|` -- decrypted data.

Steps:

1. Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2. `s <- belt-block(S, K)`.
3. For `i = 1, 2, ..., n` do:
   1. `s <- s + <1>_128`;
   2. `X_i <- Y_i ^ Lo(belt-block(s, K), |Y_i|)`.
4. Return `X = X_1 || X_2 || ... || X_n`.

## Data authentication: the `belt-mac` algorithm

Data authentication is defined by the `belt-mac` algorithm.

Input:

* `X in {0, 1}^*` -- source data;
* `K in {0, 1}^256` -- a key.

Output:

* `T in {0, 1}^64` -- the authentication tag.

Steps:

1. If `|X| > 0`, then:
   1. parse `(X_1, X_2, ..., X_n) = Split(X, 128)`.
2. Else, if `|X| = 0`, then:
   1. `let n = 1` and `X_1` be the empty word of length `0`.
3. `s <- Rep(0, 128), r <- belt-block(s, K)`.
4. Parse `(r_1, r_2, r_3, r_4) = Split(r, 32)`.
5. For `i = 1, 2, ..., n-1` do:
   1. `s <- belt-block(s ^ X_i, K)`.
6. If `|X_n| = 128`, then:
   1. `s <- s ^ X_n`;
   2. `s <- s ^ (r_2 || r_3 || r_4 || (r_1 ^ r_2))`.
7. Else, if `|X_n| < 128`, then:
   1. `s <- s ^ (X_n || 1 || Rep(0, 127 - |X_n|))`;
   2. `s <- s ^ ((r_1 ^ r_4) || r_1 || r_2 || r_3)`.
8. `T <- Lo(belt-block(s, K), 64)`.
9. Return `T`.

## Authenticated encryption in the DWP mode

Authenticated encryption in the DWP mode is defined by the data wrapping
algorithm `belt-dwp` and and the data unwrapping algorithm `belt-dwp-inv`.

### Data wrapping: the `belt-dwp` algorithm

Input:

* `X in {0, 1}^*` -- plaintext data, `|X| < 2^64`;
* `I in {0, 1}^*` -- associated data, `|I| < 2^64`;
* `K in {0, 1}^128` -- a key,
* `S in {0, 1}^128` -- a nonce.

Output:

* `Y in {0, 1}^{|X|+128}` -- the encrypted data;
* `T in {0, 1}^64` -- the authentication tag.

Steps:

1. `(X_1, X_2, ..., X_n) <- Split(X, 128)`.
2. `(I_1, I_2, ..., I_m) <- Split(I, 128)`.
3. Set:
   1. `s <- belt-block(S, K)`;
   2. `r <- belt-block(s, K)`;
   3. `t <- BeltH(0, 16)`.
4. For `i = 1, 2, ..., m` do:
   1. `t <- t ^ (I_i || Rep(0, 128 - |I_i|))`;
   2. `t <- t * r`.
5. For `i = 1, 2, ...., n` do:
   1. `s <- s + <1>_{128}`;
   2. `Y_i <- X_i ^ Lo(belt-block(s, K), |X_i|)`;
   3. `t <- t ^ (Y_i || Rep(0, 128 - |Y_i|))`;
   4. `t <- t * r`.
6. `t <- t ^ (<|I|>_{64} || <|X|>_{64})`.
7. `t <- belt-block(t * r, K)`.
8. `T <- Lo(t, 64)`.
9. Return `(Y, T)`, where `Y = Y_1 || Y_2 || ... || Y_n`.

### Data unwrapping: the `belt-dwp-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data, `|Y| < 2^64`;
* `I in {0, 1}^*` -- associated data, `|I| < 2^64`;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce;
* `T in {0, 1}^64` -- an authentication tag.

Output:

* `NULL` -- an authentication error, or `X in {0, 1}^|Y|` -- the decrypted
  data.

Steps:

1. Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2. Parse `(I_1, I_2, ..., I_m) = Split(I, 128)`.
3. Set:
   1. `s <- belt-block(S, K)`;
   2. `r <- belt-block(s, K)`;
   3. `t <- BeltH(0, 16)`.
4. For `i = 1, 2, ..., m` do:
   1. `t <- t ^ (I_i || Rep(0, 128 - |I_i|))`;
   2. `t <- t * r`.
5. For `i = 1, 2, ..., n` do:
   1. `t <- t ^ (Y_i || Rep(0, 128 - |Y_i|))`;
   2. `t <- t * r`.
6. `t <- t ^ (<|I|>_{64} || <|Y|>_{64})`.
7. `t <- belt-block(t * r, K)`.
8. If `T != Lo(t, 64)`, then return `NULL`.
9. For `i = 1, 2, ..., n` do:
   1. `s <- s + <1>_{128}`;
   2. `X_i <- Y_i ^ Lo(belt-block(s, K), |Y_i|)`.
10. Return `X = X_1 || X_2 || ... || X_n`.

## Authenticated encryption in the CHE mode

Authenticated encryption in the CHE mode is defined by the data wrapping
algorithm `belt-che` and the data unwrapping algorithm `belt-che-inv`.

The constant `C` used in the algorithm is defined as `C = 0x02 || Rep(0, 120)`;
its polynomial interpretation is `C(x) = x`.

### Data wrapping: the `belt-che` algorithm

Input:

* `X in {0, 1}^*` -- source data, `|X| < 2^64`;
* `I in {0, 1}^*` -- associated data, `|I| < 2^64`;
* `K in {0, 1}^128` -- a key,
* `S in {0, 1}^128` -- a nonce.

Output:

* `Y in {0, 1}^{|X|+128}` -- the wrapped data;
* `T in {0, 1}^64` -- the authentication tag.

Steps:

1. `(X_1, X_2, ..., X_n) <- Split(X, 128)`.
2. `(I_1, I_2, ..., I_m) <- Split(I, 128)`.
3. Set:
   1. `s <- belt-block(S, K)`;
   2. `r <- s`;
   3. `t <- BeltH(0, 16)`.
4. For `i = 1, 2, ..., m` do:
   1. `t <- t ^ (I_i || Rep(0, 128 - |I_i|))`;
   2. `t <- t * r`.
5. For `i = 1, 2, ...., n` do:
   1. `s <- (s * C) ^ <1>_{128}`;
   2. `Y_i <- X_i ^ Lo(belt-block(s, K), |X_i|)`;
   3. `t <- t ^ (Y_i || Rep(0, 128 - |Y_i|))`;
   4. `t <- t * r`.
6. `t <- t ^ (<|I|>_{64} || <|X|>_{64})`.
7. `t <- belt-block(t * r, K)`.
8. `T <- Lo(t, 64)`.
9. Return `(Y, T)`, where `Y = Y_1 || Y_2 || ... || Y_n`.

### Data unwrapping: the `belt-che-inv` algorithm

Input:

* `Y in {0, 1}^*` -- ciphertext data, `|Y| < 2^64`;
* `I in {0, 1}^*` -- associated data, `|I| < 2^64`;
* `K in {0, 1}^256` -- a key;
* `S in {0, 1}^128` -- a nonce;
* `T in {0, 1}^64` -- an authentication tag.

Output:

* `NULL` -- an authentication error, or `X in {0, 1}^|Y|` -- the decrypted data.

Steps:

1.  Parse `(Y_1, Y_2, ..., Y_n) = Split(Y, 128)`.
2.  Parse `(I_1, I_2, ..., I_m) = Split(I, 128)`.
3.  Set:
    1. `s <- belt-block(S, K)`;
    2. `r <- s`;
    3. `t <- BeltH(0, 16)`.
4.  For `i = 1, 2, ..., m` do:
    1. `t <- t ^ (I_i || Rep(0, 128 - |I_i|))`;
    2. `t <- t * r`.
5.  For `i = 1, 2, ..., n` do:
    1. `t <- t ^ (Y_i || Rep(0, 128 - |Y_i|))`;
    2. `t <- t * r`.
6.  `t <- t ^ (<|I|>_{64} || <|Y|>_{64})`.
7.  `t <- belt-block(t * r, K)`.
8.  If `T != Lo(t, 64)`, then return `NULL`.
9.  For `i = 1, 2, ..., n` do:
    1. `s <- (s * C) ^ <1>_{128}`;
    2. `X_i <- Y_i ^ Lo(belt-block(s, K), |Y_i|)`.
10. Return `X = X_1 || X_2 || ... || X_n`.

## Key wrapping

Key wrapping is defined by the key wrapping algorithm `belt-kwp` and the key
unwrapping algorithm `belt-kwp-inv`.

### Key wrapping: the `belt-kwp` algorithm

Input:

* `X in {0, 1}^8*` -- a source key;
* `I in {0, 1}^128` -- the header of `X`;
* `K in {0, 1}^128` -- a key.

Output:

* `Y in {0, 1}^{|X|+128}` -- the wrapped key.

Steps:

1. `Y <- belt-wblock(X || I, K)`.
2. Return `Y`.

### Key unwrapping: the `belt-kwp-inv` algorithm

Input:

* `Y in {0, 1}^*` -- a wrapped key;
* `I in {0, 1}^128` -- the header of `Y`;
* `K in {0, 1}^128` -- a key.

Output:

* `NULL` -- an authentication error, or `X in {0, 1}^{|Y|-128}` -- the
  unwrapped key.

Steps:

1. If `|Y|` is not a multiple of `8` or `|Y| < 256`, then return `NULL`.
2. `(X || r) <- belt-wblock-inv(Y, K)`, where `|X| = |Y| - 128`, `|r| = 128`.
3. If `r != I`, then return `NULL`.
4. Return `X`.

## Hashing: the `belt-hash` algorithm

Hashing is defined by the `belt-hash` algorithm.

Input:

* `X in {0, 1}^*` -- source data.

Output:

* `H in {0, 1}^256` -- the hash value.

Steps:

1. Parse `(X_1, X_2, ..., X_n) = Split(X, 256)`.
2. `r <- <|X|>_128`.
3. `s <- Rep(0, 128)`.
4. `h <- BeltH(0, 32)`.
5. `X_n <- X_n || Rep(0, 256 - |X_n|)`.
6. For `i = 1, 2, ..., n`:
   1. `(t, h) <- belt-compress(X_i || h)`;
   2. `s <- s ^ t`.
7. `(NULL, H) <- belt-compress(r || s || h)`.
8. Return `H`.

## Key expansion: the `belt-keyexpand` algorithm

Key expansion is defined by the `belt-keyexpand` algorithm.

Input:

* `X in {0, 1}^n` -- a source key, `n in {128, 192, 256}`.

Output:

* `Y in {0, 1}^256` -- the expanded key.

Steps:

1. If `|X| = 128`, then `Y <- X || X`.
2. Else if `|X| = 192`, then:
   1. `(X_1, X_2, X_3) <- Split(X, 64)`;
   2. `Y <- X_1 || X_2 || X_3 || (X_1 ^ X_2 ^ X_3)`.
3. Else, if `|X| = 256`, then `Y <- X`.
4. Return `Y`.

## Key derivation: the `belt-keyrep` algorithm

Key derivation is defined by the algorithm `belt-keyrep`.

Input:

* `X in {0, 1}^n` -- a source key, `n in {128, 192, 256}`;
* `D in {0, 1}^96` -- the depth of `X`;
* `I in {0, 1}^128` -- the header used for deriving the output key;
* `m in {128, 192, 256}` -- the length used for deriving the output key,
  `m <= n`.

Output:

* `Y in {0, 1}^m` -- the derived key.

Steps:

1. `r <- BeltH(n/2 + m/4 - 96, 4)`.
2. `s <- belt-keyexpand(X)`.
3. `(NULL, s) <- belt-compress(r || D || I || s)`.
4. `Y <- Lo(s, m)`.
5. Return `Y`.

# Bign algorithms {#BIGN}

## Preliminaries

Bign is a family of asymmetric (public-key) cryptographic algorithms that
implement the digital signature and key transport mechanisms. The purpose of
digital signature is to establish control of data authenticity. The purpose of
key transport is to provide confidentiality and control authenticity of
symmetric keys. In applications, data is usually authenticated or encrypted
using a secret key, and this key is protected by the key transport mechanism.

Bign algorithms relate to Elliptic Curve Cryptography {{HMV04}} by their use of
elliptic curves as an underlying mathematical primitive. The requirements
imposed on these elliptic curves are denoted as `bign-curves`.

Bign algorithms are the following:

- `bign-sign` -- digital signature: generating signatures;
- `bign-vfy` -- digital signature: verifying signatures;
- `bign-keyt` -- key transport: wrapping keys;
- `bign-keyt-inv` -- key transport: unwrapping keys.

Regular Bign algorithms are supported by the following key management algorithms:

* `bign-genkeypair` -- generating key pairs;
* `bign-valpubkey` -- validating public keys;
* `belt-genk` -- generating ephemeral private keys (for `bign-sign`).

The `bign-sign` and `bign-vfy` algorithms implement the Schnorr signature
scheme {{Sch91}}. By truncating the hash parts of the signatures, `bign-sign`
reduces their size to 48, 72, or 96 octets depending on the security level.

The `bign-keyt` algorithm wraps the transported key by invoking `belt-kwp` with an
ephemeral key generated by a Diffie-Hellman-based key encapsulation mechanism
(see {{RFC9180}}). The use of `belt-kwp` allows for key wrapping without relying on
a complicated KDF (key derivation function). The `bign-keyt` algorithm provides
confidentiality and integrity control of the transported keys.

The `bign-sign` and `bign-keyt` algorithms are probabilistic: they rely on randomly
generated ephemeral private keys. However, a deterministic mode is also provided
for `bign-sign` based on the `bign-genk` algorithm.

The `bign-genk` algorithm constructs an ephemeral key from the signer's private
key, the hash value of the signed data, and (optionally) an additional data
chunk that can be random.

## Security levels

The sizes of Bign objects (elliptic curve parameters, keys, signatures, etc.)
depend on the security level `l in {128, 192, 256}`.

At level `l`, the complexity of recovering an unknown private key from a known
public key is of the order `2^l` operations. The same estimate holds for related
cryptanalytic problems: forging a digital signature or decrypting a transported
key.

## Elliptic curves

Elliptic curves are constructed over large prime finite fields. They are of the
short Weierstrass form. The corresponding definitions are given below.

* `FF_p`: for an odd prime `p`, the set `{0, 1, ..., p-1}` whose elements are
  added and multiplied modulo `p` (the finite field of order `p`);
* `a, b`: elements of `FF_p` such that `(4*a^3 + 27*b^2) mod p != 0`;
* `E_{a,b}`: the equation `y^2 = x^3 + a*x + b`;
* `O`: the point at infinity;
* `E_{a,b}(FF_p)^*`: the set of pairs `(x, y)`, where `x` and `y` lie in `FF_p`
  and satisfy the equation `E` (affine points);
* `E_{a,b}(FF_p)`: the union of sets `E_{a,b}(FF_p)^*` and `{O}`.

The set `E_{a,b}(FF_p)` is an Abelian group under addition. The addition
operation is defined as follows.

1. If `P in E_{a,b}(FF_p)`, then `O + P = P + O = P`.
2. If `P = (x, y) in E_{a,b}(FF_p)^*`, then `-P = (x, p - y)` and
   `P + (-P) = O`.
3. `-O = O`.
4. If `P_1 = (x_1, y_1) in E_{a,b}(FF_p)^*`,
  `P_2 = (x_2, y_2) in E_{a,b}(FF_p)^*` and `P_1 != -P_2`,
   then `P_1 + P_2 = (x_3, y_3)`, where
   * `x_3` = `lambda^2 - x_1 - x_2` and
   * `y_3` = `lambda*(x_1 - x_3) - y_1` with
     - `lambda = (y_2 - y_1)/(x_2 - x_1) if P_1 != P_2` and
     - `lambda = (3*x_1^2 + a)/(2*y_1) if P_1 = P_2` (calculations modulo `p`).

Given a point `G in E_{a,b}(FF_p)*`, its multiples are defined as
`2 G = G + G`, `3 G = 2 G + G, ...`. The order of `G` is the smallest positive
integer `q` such that `q G = O`.

A point `G` of order q generates a cyclic group `GG_q` of the same order:
`GG_q = {O,G, 2 G, ..., (q-1)G}`. In the Bign algorithms, the group `GG_q` is
always equal to the entire group `E_{a,b}(FF_p)`. In particular,
`GG_q^* = E_{a,b}(FF_p)^*`.

Points of `GG_q^*` are encoded as follows.

* `<P>`: for `P in GG_q^*`, `P = (x, y)`, the word `<x>_{2*l} || <y>_{2*l}`;
* `<P>_m`: for `P = (x, y) in GG_q^*` and a positive integer `m < 4*l`, the
  word `Lo(<P>, m)`.

## The `bign-curves` requirements

Algorithms of the Bign family use elliptic curve parameters `(p, a, b, q, y_G)`,
that specify the elliptic curve `E` over `FF_p`, the base point
`G = (0, y_G) in E_{a,b}(FF_p)^*`, its order `q` and the cyclic group `GG_q`
generated by `G`.

Elliptic curve parameters have to satisfy general requirements defined above
and additional requirements motivated by security, convenience of
implementation, compactness of data representation and transparency.

The full list of requirements, called `bign-curves`, is as follows.

1.  At the security level `l in {128, 192, 256}` it holds that 
    `2^{2*l-1} < p, q < 2^{2*l}`.
2.  `p` and `q` are prime numbers.
3.  `p != q`.
4.  `p mod 4 = 3`.
5.  `p^m mod q != 1` for `m = 1, 2,..., 50`.
6.  `0 < a`, `b < p`.
7.  `b = [belt-hash(<p>_{2*l} || <a>_{2*l} || seed)] mod p`, where 
    `seed in {0, 1}^{64}` is an initialization parameter for the curve 
    generation algorithm.
8.  `b^{(p-1)/2} mod p = 1`, i.e., `b` is a quadratic residue modulo `p`.
9.  `(4 a^3 + 27 b^2) mod p != 0`.
10. `G = (0, y_G)`, where `y_G = b^{(p+1)/4} mod p`.
11. `q G = O`.

**Remark**. The use of hashing in construction of the coefficient `b` makes the
resulting elliptic curve pseudorandom.

Recommended elliptic curves for each of the three Bign security levels are given
in {{CURVES}}. All of them were generated pseudorandomly using the procedure
outlined above.

## Keys

Private keys are nonzero integers modulo `q` and public keys are nonzero
elements of `GG_q`.

Private keys are used in `bign-sign` to sign messages and in `bign-keyt-inv` to
unwrap transported keys. The corresponding public keys are used in `bign-vfy`
to verify signatures and in `bign-keyt` to wrap keys.

It is allowed to use the same private key in both the `bign-sign` and `bign-keyt`
algorithms. Thus, both digital signatures and key transport can rely on a single
public key certificate.

In addition to long-term or static key pairs discussed above, the `bign-sign`
and `bign-keyt` algorithms use short-term or ephemeral key pairs. The ephemeral
keys have the same structure as static keys.

Private keys (both static and ephemeral) must be generated using random number
generators or pseudorandom number generators with secret parameters of
sufficient length (entropy). In `bign-sign`, it is allowed to use the
`bign-genk` algorithm for ephemeral key generation.

## Key management

Key management is defined by the key pair generation algorithm
`bign-genkeypair`, the public key validation algorithm `bign-valpubkey`, and
the ephemeral key generation algorithm `bign-genk`.

The algorithms use the following public parameters:

* elliptic curve parameters `(p, a, b, q, y_G)` that satisfy the `bign-curves`
  requirements and determine:
  - the security level `l` -- the minimum positive integer such that
    `p < 2^{2*l}`;
  - the group `GG_q = E_{a,b}(FF_p)` of order `q`;
  - the base point `G = (0, y_G) in GG_q`.

The `bign-genk` algorithm uses an additional public parameter:

* the identifier `OID(h)` of a hashing algorithm `h`.

## Key pair generation: the `bign-genkeypair` algorithm

Input:

* `NULL`.

Output:

* `d in {1, 2, ..., q-1}` -- a private key;
* `Q in GG_q^*` -- the corresponding public key.

Steps:

1. `d <- {1, 2, ..., q-1}`.
2. `Q <- d G`.
3. Return `(d, Q)`.

## Public key validation: the `bign-valpubkey` algorithm

Input:

* `Q in GG_q^*` -- a public key.

Output:

* `1` if `Q` is valid, and `0` otherwise.

Steps:

1. Parse `Q = (x_Q, y_Q)`, where `x_Q` and `y_Q` are integers.
2. If either condition:
   * `0 <= x_Q, y_Q < p`;
   * `y_Q^2 mod p = (x_Q^3 + a * x_Q + b) mod p`;

   is violated, then return 0.
3. Return 1.

## Generating ephemeral keys: the `bign-genk` algorithm

Input:

* `d in {1, 2, ..., q-1}` -- a private key;
* `H in {0, 1}^{2*l}` -- a hash value.

Output:

* `k in {1, 2, ..., q-1}` -- an ephemeral private key.

Steps:

1. Pick an arbitrary `t in {0, 1}^*` (t can be an empty word).
2. `K <- belt-hash(OID(h) || <d>_{2*l} || t)`.
3. `r <- H`.
4. Represent `r` as the tuple `(r_1, r_2, ..., r_n) = Split(r, 128)`.
5. For `i = 1, 2, ...` do:
   1. if `n = 2`, then:
      1. `s <- r_1`;
   2. if `n = 3`, then:
      1. `s <- r_1 ^ r_2`;
      2. `r_1 <- r_2`;
   3. if `n = 4`, then:
      1. `s <- r_1 ^ r_2 ^ r_3`;
      2. `r_1 <- r_2`;
      3. `r_2 <- r_3`;
   4. `r_{n-1} <- belt-block(s, K) ^ r_n ^ <i>_{128}`;
   5. `r_n <- s`;
   6. if `i mod 2*n = 0` and `r in {1, 2, ..., q-1}`, go to Step 6.
6. `k <- r`.
7. Return `k`.

## Digital signatures

Digital signature procedures are defined by the signature generation algorithm
`bign-sign` and the signature verification algorithm `bign-vfy`.

Both algorithms use the following public parameters:

* elliptic curve parameters `(p, a, b, q, y_G)` that satisfy the `bign-curves`
  requirements and determine:
  - the security level `l` -- the minimum positive integer such that
    `p < 2^{2*l}`;
  - the group `GG_q = E_{a,b}(FF_p)` of order `q`;
  - the base point `G = (0, y_G) in GG_q`;
* the hashing algorithm `h` that returns `2*l`-bit hash values and is
  identified by `OID(h)`.

Public parameters are propagated to the nested key management algorithms.

## Signing: the `bign-sign` algorithm

Input:

* `X in {0, 1}^*` -- the message to be signed;
* `d in {1, 2, ..., q-1}` -- a private key.

Output:

* `S in {0, 1}^{3*l}` -- the signature.

Steps:

1. `H <- h(X)`.
2. If the signing mode is probabilistic, then
   1. `(k, R) <- bign-genkeypair()`.
3. Else, if the signing mode is deterministic, then
   1. `k <- bign-genk(d, H)`;
   2. `R <- k G`.
4. `S_0 <- <belt-hash(OID(h) || <R>_{2l} || H)>_l`.
5. `S_1 <- <(k - [H] - ([S_0] + 2^l)d) mod q>_{2l}`.
6. `S <- S_0 || S_1`.
7. Return `S`.

## Verifying: the `bign-vfy` algorithm

Input:

* `X in {0, 1}^*` -- a signed message;
* `S in {0, 1}^*` -- a signature;
* `Q in GG_q^*` -- a public key.

Output:

* `1`, if the signature is valid, and `0` otherwise.

Steps:

1. If `|S| != 3l`, then return `0`.
2. Parse `S = S0 || S1`, where `|S0| = l` and `|S1| = 2*l`.
3. If `[S1] >= q`, then return `0`.
4. `H <- h(X)`.
5. `R <- (([S1] + [H]) mod q)G + ([S0] + 2^l)Q`.
6. If `R = O`, then return `0`.
7. `t <- Lo(belt-hash(OID(h) || <R>_{2l} || H), l)`.
8. `If S0 != t`, then return `0`.
9. Return `1`.

## Key transport

Key transport is defined by the key wrapping algorithm `bign-keyt` and the key
unwrapping algorithm `bign-keyt-inv`.

Both algorithms use the following public parameters:

* elliptic curve parameters `(p, a, b, q, y_G)` that satisfy the `bign-curves`
requirements and determine:
  - the security level `l` -- the minimum positive integer such that
    `p < 2^{2*l}`;
  - the group `GG_q = E_{a,b}(FF_p)` of order `q`;
  - the base point `G = (0, y_G) in GG_q`.

Public parameters are propagated to the nested key management algorithms.

### Key wrapping: the `bign-keyt` algorithm

Input:

* `X in {0, 1}^8*` -- the key to wrap, `|X| >= 128`;
* `I in {0, 1}^128` -- the header of `X`;
* `Q in GG_q^*` -- the public key (of the recipient).

Output:

* `Y in {0, 1}^{2*l+|X|+128}` -- the wrapped key.

Steps:

1. `(k, R) <- bign-genkeypair()`.
2. `K <- <k Q>_{256}`.
3. `Y <- <R>_{2*l} || belt-keywrap(X, I, K)`.
4. Return `Y`.

### Key unwrapping: the `bign-keyt-inv` algorithm

Input:

* `Y in {0, 1}^*` -- the key to unwrap;
* `I in {0, 1}^{128}` -- the header of `Y`;
* `d in {1, 2, ..., q-1}` -- a private key.

Output:

* `NULL` -- integrity error, or `X in {0, 1}^{|Y|-128-2*l}` -- the unwrapped
  key.

Steps:

1.  If `|Y|` is not a multiple of 8 or `|Y| < 2*l + 256`, then return `NULL`.
2.  Parse `Y = Y_0 || Y_1`, where `|Y_0| = 2*l` and `|Y_1| = |Y| - 2*l`.
3.  `x_R <- [Y_0]`.
4.  if `x_R >= p`, then return `NULL`.
5.  `y_R <- (x_R^3 + a*x_R + b)^{(p+1)/4} mod p`.
6.  `R <- (x_R, y_R)`.
7.  If `bign-valpubkey(R) != 1`, then return `NULL`.
8.  `K <- <d R>_{256}`.
9.  If `belt-kwp-inv(Y_1, I, K) = NULL`, then return `NULL`.
10. `X <- belt-kwp-inv(Y_1, I, K)`.
11. Return `X`.

# Bake protocols {#BAKE}

## Preliminaries

Bake is a family of cryptographic protocols that implement authenticated
key establishment.

Bake algorithms use elliptic curves that meet the `bign-curves` requirements.

Bake protocols are the following:

* `bake-bmqv` -- the protocol implementing the MQV {{LMQSV03}} scheme;
* `bake-bsts` -- the protocol implementing the STS {{DOW92}} scheme;
* `bake-bpace` -- the protocol implementing the PACE {{BFK09}} scheme.

The `bake-bmqv` and `bake-bsts` protocols use ephemeral digital signatures similar
to the Bign digital signatures. In the `bake-bsts` protocol, ephemeral signatures
and ephemeral public keys are generated simultaneously, which improves
performance.

The `bake-bmqv` and `bake-bsts` protocols allow two parties to establish a shared
secret key using static private keys. Each party must have knowledge of the other
party's public key. `Bake-bmqv` is more computationally efficient, however,
`bake-bsts` has the advantage of user anonymity: a passive adversary cannot
identify the parties participating in the protocol.

The `bake-bpace` protocol allows two parties to establish a shared secret key
using a pre-shared secret password. The underlying PACE scheme makes it
computationally infeasible to determine the password from the protocol
messages, even if the password is short or has low entropy. An active adversary
can only check a single candidate password per one protocol session.

All protocols in the Bake family ensure confidentiality of the established
shared keys. In addition, the protocols allow for explicit key confirmation:
either party, or both parties, may verify that the same key was established on
the other side of the protocol. Key confirmation is mandatory in `bake-bsts` and
optional in `bake-bmqv` and `bake-bpace`.

Successful key confirmation in the `bake-bpace` protocol verifies the knowledge of
the shared secret password by the other party, i.e., the protocol can be used
for mutual authentication.

Successful key confirmation in the `bake-bmqv` and `bake-bsts` protocols
verifies the knowledge of the private keys corresponding to the transmitted
public keys by both parties. The `bake-bmqv` protocol thus provides mutual
authentication since key confirmation relies on public key certificates; the
`bake-bsts` protocol provides mutual authentication if the correspondence
between the identifiers of the parties and the static public keys has been
verified (e.g., via verification of public key certificates independent of the
protocol).

Bake protocols are supported by the following auxiliary algorithms:

* `bake-kdf` -- key derivation;
* `bign-swu` -- hashing to elliptic curves.

The design of the `bign-swu` algorithm follows {{BCIMRT10}}.

## Elliptic curve parameters

The `bake-bmqv`, `bake-bsts` and `bake-bpace` protocols use elliptic curve
parameters `(p, a, b, q, y_G)` that satisfy the `bign-curves` requirements and
determine:

* the `security level l` -- the minimum positive integer such that `p < 2^{2*l}`;
* the `group GG_q = E_{a,b}(FF_p)` of order `q`;
* the `base point G = (0, y_G) in GG_q`.

## Keys

The Bake protocols use the same private and public keys as the Bign family. All
protocols use ephemeral key pairs, the `bake-bmqv` and `bake-bsts` protocols also use
static key pairs, and the `bake-bpace` protocol uses symmetric ephemeral secret keys.

Private and secret keys must be generated using random number generators or
pseudorandom number generators with secret parameters of sufficient length
(entropy). This requirement is propagated to the `bign-genkeypair` algorithm
used in the protocols.

## Certificates

The `bake-bqmv` and `bake-bake-bsts` protocol assume that each party has their
static public key `Q` bound to its identifier Id and distributed in the form of a
certificate `Cert(Id, Q)`. The certificate is validated by the other party as the
protocol is executed. During the validation, it must be verified that the
binding between `Id` and `Q` is valid and that `Q` belongs to `GG_q^*`. The
last check must be performed by calling the  `bign-valpubkey` algorithm.

In the `bake-bmqv` protocol, the transmission and verification of the
certificate can be performed in advance (before the protocol session) or
implicitly.

This specification does not regulate the content and format of the
certificates, or their method of validation. However, the security of
certificate validation determines the security of authentication in the
`bake-bmqv` and `bake-bsts` protocols. Typically, X.509 certificates are used,
and their validation relies on verifying a digital signature of a trusted party
(certificate authority), or a chain of digital signatures.

When issuing `Cert(Id, Q)`, the issuer may check that the intended certificate
holder has the knowledge of the private key `d` corresponding to `Q`. This proof of
possession can be performed implicitly in the `bake-bmqv` or `bake-bsts` protocol,
or explicitly by asking the intended holder to produce a digital signature of
the certificate data, including `Id` and `Q`, using the private key `d`. If the
signature is then verified to be valid, it proves the possession of `d`.

The above proof of possession must use the `bign-sign` and `bign-vfy` algorithms
with the same elliptic curve parameters as the target protocol.

## Hello messages

The protocols are initiated by exchanging hello messages. First, party `A` sends
a message `hello_A`. This message may include a list of elliptic curves that
are suitable to `A`, a password hint, a timestamp, etc. Party `B` replies with
a message `hello_B`, which may include similar data.

The content of hello messages affects the construction of the shared key.
Therefore, adversarial modification of hello messages (for example, to downgrade
protocol settings) will be detected by the parties of the protocols.

This specification does not regulate the format of hello messages. Their
transmission and processing can be performed in advance or implicitly.

By default, `hello_A` and `hello_B` are empty words. This assumes that the parties
have agreed upon public parameters in advance and that volatile data, such as
timestamps, will not be used in the protocols.

## Key derivation: the `bake-kdf` algorithm

Key derivation is defined by the `bake-kdf` algorithm.

Input:

* `X in {0, 1}^*` -- secret data;
* `S in {0, 1}^*` -- additional data;
* `C in {0, 1, ...}` -- the number of the key to be derived.

Output:

* `Y in {0, 1}^256` -- the derived key.

Steps:

1. `Y <- belt-hash(X || S)`.
2. `Y <- belt-keyrep(Y, Rep(1, 96), <C>_{128}, 256)`.
3. Return `Y`.

## Hashing to elliptic curves: the `bake-swu` algorithm

Hashing to elliptic curves in defined by the `bake-swu` algorithm.

Parameters:

* elliptic curve parameters `(p, a, b, q, y_G)` that satisfy the `bign-curves`
  requirements and determine:
  - the security level `l` -- the minimum positive integer such that
   `p < 2^{2*l}`;
  - the group `GG_q = E_{a,b}(FF_p)` of order `q`.

Input:

* `X in {0, 1}^{2*l}`.

Output:

* `W = (x, y) in GG_q^*`.

Steps:

1.  `H <- belt-keywrap(X, Rep(0, 128), Rep(0, 256))`.
2.  `s <- [H] mod p`.
3.  `t <- -s^2 mod p`.
4.  `x_1 <- -b (1 + t + t^2) (a(t + t^2))^{p-2} mod p`.
5.  `x_2 <- t x_1 mod p`.
6.  `y <- ((x_1)^3 + a x_1 + b) mod p`.
7.  `s <- s^3 y mod p`.
8.  `t <- y^{p-1-(p+1)/4} mod p`.
9.  If `(t^2 y) mod p = 1`, then `W <- (x_1, t y mod p)`.
10. Else, if `(t^2 y) mod p != 1`, then `W <-(x_2, s t mod p)`.
11. Return `W`.

## The `bake-bmqv` protocol

Input:

* `d_A in {1, 2, ..., q-1}` -- the private key of `A` (used only by `A`);
* `Cert(Id_A, Q_A) in {0, 1}^*` -- the public key certificate of `A`;
* `d_B in {1, 2, ..., q-1}` -- the private key of `B` (used only by `B`);
* `Cert(Id_B, Q_B) in {0, 1}^*` -- the public key certificate of `B`.

Output:

* `NULL` or `K_0 in {0, 1}^256` -- the shared key.

Messages:

* `M0 (A to B): {{ hello_A }}`;
* `M1 (B to A): {{ hello_B || }} {{ Cert (Id_B, Q_B) || }} <V_B>_{4*l}`;
* `M2 (A to B): {{ Cert(Id_A, Q_A) }} <V_A>_{4l} [[ || T_A ]]`;
* `M3 (B to A): [[ T_B ]]`.

Steps:

1. Party `A`:
   1. `{{ sends M0 }}`;
2. Party `B`:
   1. `{{ receives M0 }}`;
   2. `(u_B, V_B) <- bign-genkeypair()`;
   3. sends `M1`.
3. Party `A`:
   1.  receives `M1`;
   2.  `{{ verifies Cert(Id_B, Q_B) }}`;
   3.  verifies that `bign-valpubkey(V_B) = 1`;
   4.  `(u_A, V_A) <- bign-genkeypair()`;
   5.  `t <- Lo(belt-hash(<V_A>_{2*l} || <V_B>_{2*l}), l)`;
   6.  `s_A <- (u_A - (2^l + [t])d_A) mod q`;
   7.  `K <- s_A (V_B - (2^l + [t]))Q_B`;
   8.  if `K = O`, then `K <- G`;
   9.  `K_0 <- bake-kdf(<K>_{2*l}, Cert(Id_A, Q_A) || Cert(Id_B, Q_B) || hello_A || hello_B, 0)`;
   10. `[[ K_1 <- bake-kdf(<K>_{2*l}, Cert(Id_A, Q_A) || Cert(Id_B, Q_B) || hello_A || hello_B, 1) ]]`;
   11. `[[ T_A <- belt-mac(Rep(0, 128), K_1) ]]`;
   12. sends `M2`.
4. Party `B`:
   1. receives `M2`;
   2. `{{ verifies Cert(Id_A, Q_A) }}`;
   3. verifies that `bign-valpubkey(V_A) = 1`;
   4. `t <- Lo(belt-hash(<V_A>_{2*l} || <V_B>_{2*l}), l)`;
   5. `s_B <- (u_B - (2^l + [t]) d_B) mod q`;
   6. `K <- s_B(V_A - (2^l + [t]))Q_A`;
   7. if `K = O`, then `K <- G`;
   8. `K_0 <- bake-kdf(<K>_{2*l}, Cert(Id_A, Q_A) || Cert(Id_B, Q_B) || hello_A || hello_B, 0)`;
   9. `[[ K_1 <- bake-kdf(<K>_{2*l}, Cert(Id_A, Q_A) || Cert(Id_B, Q_B) || hello_A || hello_B, 1); ]]`
   10. `[[ verifies that T_A = belt-mac(Rep(0, 128), K_1); ]]`
   11. `[[ T_B <- belt-mac(Rep(1, 128), K_1); ]]`
   12. sends `M3`.
5. Party `A`:
   1. `[[ receives M3; ]]`
   2. `[[ verifies that T_B = belt-mac(Rep(1, 128), K_1). ]]`

If an error occurs at any of the steps, including failures of any verification
steps, then the protocol is immediately terminated and `NULL` is returned.

Successful execution of the protocol means that the parties have established a
shared secret key `K_0`. If the authentication tag `T_A (T_B)` was generated and
verified, successful execution of the protocol also means that the party `A` (`B`)
has proved the possession of their private key and the shared key. Therefore,
the party `A` (`B`) has also authenticated themselves to `B` (`A`).

## The `bake-bsts` protocol

Input:

* `d_A in {1, 2, ..., q-1}` -- the private key of `A` (used only by `A`);
* `Cert(Id_A, Q_A) in {0, 1}^*` -- the public key certificate of `A`;
* `d_B in {1, 2, ..., q-1}` -- the private key of `B` (used only by `B`);
* `Cert(Id_B, Q_B) in {0, 1}^*` -- the public key certificate of `B`.

Output:

* `NULL` or `K_0 in {0, 1}^256` -- shared key.

Messages:

* `M0 (A to B): {{ hello_A }}`;
* `M1 (B to A): {{ hello_B || }} <V_B>_{4*l}`;
* `M2 (A to B): <V_A>_{4l}  || Y_A || T_A`;
* `M3 (B to A): Y_B || T_B`.

Steps:

1. Party `A`:
   1. sends `M0`.
2. Party `B`:
   1. receives `M0`;
   2. `(u_B, V_B) <- bign-genkeypair()`;
   3. Sends `M1`.
3. Party `A`:
   1.  receives `M1`;
   2.  verifies that `bign-valpubkey(V_B) = 1`;
   3.  `(u_B, V_B) <- bign-genkeypair()`;
   4.  `K <- u_A V_B`;
   5.  `K_0 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 0)`;
   6.  `K_1 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 1)`;
   7.  `K_2 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 2)`;
   8.  `t <- Lo(belt-hash(<V_A>_{2*l} || <V_B>_{2*l}), l)`;
   9.  `s_A <- (u_A - (2^l + [t])d_A) mod q`;
   10. `Y_A <- belt-cfb(<s_A>_{2*l} || Cert(Id_A, Q_A), K_2, Rep(0, 128))`;
   11. `T_A <- belt-mac(Y_A || Rep(0, 128), K_1)`;
   12. sends `M2`.
4. Party `B`:
   1.  receives `M2`;
   2.  verifies that `bign-valpubkey(V_A) = 1`;
   3.  `K <- u_B V_A`;
   4.  `K_0 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 0)`;
   5.  `K_1 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 1)`;
   6.  `K_2 <- bake-kdf(<K>_{2*l}, hello_A || hello_B, 2)`;
   7.  verifies that `T_A = belt-mac(Y_A || Rep(0, 128), K_1)`;
   8.  `(<s_A>_{2*l} || Cert(Id_A, Q_A)) <- belt-cfb-inv(Y_A, K_2, Rep(0, 128))`;
   9.  verifies that `s_A in {0, 1, ..., q-1}`;
   10. verifies `Cert(Id_A, Q_A)`;
   11. `t <- Lo(belt-hash(<V_A>_{2*l} || <V_B>_{2*l}), l)`;
   12. verifies that `s_A G + (2^l + [t])Q_A = V_A`;
   13. `s_B <- (u_B - (2^l + [t]) d_B) mod q`;
   14. `Y_B <- belt-cfb(<s_B>_{2*l} || Cert(Id_B, Q_B), K_2, Rep(1, 128))`;
   15. `T_A <- belt-mac(Y_B || 1^{128}, K_1)`.
   16. sends `M3`.
5. Party `A`:
   1. receives `M3`;
   2. verifies that `T_B = belt-mac(1^{128}, K_1)`;
   3. `(<s_B>_{2*l} || Cert(Id_B, Q_B)) <- belt-cfb-inv(Y_B, K_2, Rep(1, 128))`;
   4. verifies that `s_B in {0, 1, ..., q-1}`;
   5. verifies `Cert(Id_B, Q_B)`;
   6. verifies that `s_B G + (2^l + [t])Q_B = V_B`.

If an error occurs at any of the steps, including failures of any verification
steps, then the protocol is immediately terminated and `NULL` is returned.

Successful execution of the protocol means that the parties have established a
shared secret key `K_0`, and also proved the possession of their private keys and
the shared key. Therefore, the parties have also performed mutual authentication.

## The `bake-bpace` protocol

Input:

* `P in {0, 1}^8*` -- password (used by `A` and `B`).

Output:

* `NULL` or `K_0 in {0, 1}^256` -- shared key.

Messages:

* `M0 (A to B): {{ hello_A }}`;
* `M1 (B to A): {{ hello_B || }} Y_B`;
* `M2 (A to B): Y_A || <V_A>_{4*l}`;
* `M3 (B to A): <V_B>_{4*l} [[ || T_B ]]`;
* `M4 (A to B): [[ T_A ]]`.

Steps:

1. Party `A`:
   1. sends `M0`.
2. Party `B`:
   1. receives `M0`;
   2. `R_B <- {0, 1}^l`;
   3. `K_2 <- belt-hash(P)`;
   4. `Y_B <- belt-ecb(R_B, K_2)`;
   5. sends `M1`.
3. Party `A`:
   1. receives `M1`;
   2. verifies that `|V_B| = l`;
   3. `K_2 <- belt-hash(P)`;
   4. `R_B <- belt-ecb-inv(Y_B, K_2)`;
   5. `R_A <- {0, 1}^l`;
   6. `Y_A <- belt-ecb(R_A, K_2)`;
   7. `W <- bake-swu(R_A || R_B)`;
   8. `u_A <- {1, 2, ..., q-1}`;
   9. `V_A <- u_A W`;
   10. sends `M2`.
4. Party `B`:
   1.  receives `M2`;
   2.  verifies that `bign-valpubkey(V_A) = 1`;
   3.  verifies that `|Y_A| = l`;
   4.  `R_A <- belt-ecb-inv(Y_A, K_2)`;
   5.  `W <- bake-swu(R_A || R_B)`;
   6.  `u_B <- {1, 2, ..., q-1}`;
   7.  `V_B <- u_B W`;
   8.  `K <- u_B V_A`;
   9.  `K_0 <- bake-kdf(<K>_{2*l}, <V_A>_{2*l} || <V_B>_{2*l} || hello_A || hello_B, 0)`;
   10. `[[ K_1 <- bake-kdf(<K>_{2*l}, <V_A>_{2*l} || <V_B>_{2*l} || hello_A || hello_B, 1) ]]`;
   11. `[[ T_B <- belt-mac(Rep(1, 128), K_1) ]]`;
   12. sends `M3`.
5. Party `A`:
   1. receives `M3`;
   2. verifies that `bign-valpubkey(V_B) = 1`;
   3. `K <- u_A V_B`;
   4. `K_0 <- bake-kdf(<K>_{2*l}, <V_A>_{2*l} || <V_B>_{2*l} || hello_A || hello_B, 0)`;
   5. `[[ K_1 <- bake-kdf(<K>_{2*l}, <V_A>_{2*l} || <V_B>_{2*l} || hello_A || hello_B, 1) ]]`;
   6. `[[ verifies that T_B = belt-mac(Rep(1, 128), K_1) ]]`;
   7. `[[ T_A <- belt-mac(Rep(0, 128), K_1) ]]`;
   8. sends `M4`.
6. Party `B`:
   1. `[[ receives M4 ]]`;
   2. `[[ verifies that T_A = belt-mac(Rep(0, 128), K_1) ]]`.

If an error occurs at any of the steps, including failures of any verification
steps, then the protocol is immediately terminated and `NULL` is returned.

Successful execution of the protocol means that the parties have established a
shared secret key `K_0`. If the authentication tag `T_A (T_B)` was generated and
verified, successful execution of the protocol also means that the party `A (B)`
has proved the possession of their private key and the shared key. Therefore,
the party `A (B)` has also authenticated themselves to `B (A)`.

--- back

# Recommended elliptic curves {#CURVES}

## Preliminaries

The following elliptic curves are recommended for the Bign and Bake
families:

* `bign-curve256v1` -- a curve of security level l = 128;
* `bign-curve384v1` -- a curve of security level l = 192;
* `bign-curve512v1` -- a curve of security level l = 256.

The recommended curves satisfy the `bign-curves` requirements 1 -- 11
and the following additional requirements:

12. `p` is the largest suitable prime below `2^{2*l}`.
13. `a = p - 3`.
14. Both numbers `q-1` and `q+1` have large prime factors.

Requirement 12 speeds up reduction modulo p. Requirement 13 speeds up point
doubling on elliptic curves. Requirement 14 provides protection from Cheon's
attack {{Che10}}. The attack is not directly applicable to the Bign and Bake
algorithms, but the recommended curves were chosen to satisfy requirement 14
in order to enable their use outside the scope of the respective standards.

For a given security level, the recommended curve was generated as follows:

* 50 curves satisfying the requirements 1 -- 13 were constructed from the
  smallest possible `[seed]` values, starting at `0`;
* among these curves, the one corresponding to the maximum of the value
  `min(gpf(q-1), gpf(q+1))` was chosen.

Here `gpf(n)` denotes the greatest prime factor of `n`.

The recommended curves are given below as combinations of the parameters
`(p, a, b, q, y_G)`. Seed values used to construct the curves and factorizations
of `q-1` and `q+1` are also given. The notation `r_m` is used for prime numbers of
bit length `m`.

## The `bign-curve256v1` curve

Parameters:

* `p = 2^{256} - 189`;
* `a = p - 3`;
* `b = 54189945433829174764701416670523239872420438478408031144987871676190519198705`;
* `q = 2^{256} - 51359303463308904523350978545619999225`;
* `y_G = 48835626907528736105417095645674365354469331933013114027389791773001019124371`.

Additional details:

* `seed = 0x5E38010000000000`;
* `q - 1 = 2 * 3 * 5 * 59 * 2707 * 8287 * r_{221}`;
* `q + 1 = 2^3 * 7 * 449 * 31327 * r_{227}`.

## The `bign-curve384v1` curve

Parameters:

* `p = 2^{384} - 317`;
* `a = p - 3`;
* `b = 9305714544225430607690103672579840289571010502599374151660380\
       432967684614892230431863267093750334370523665755520868`;
* `q = 2^{384} - 9886438520659958522437788006980660965037549058207958390857`;
* `y_G = 14354597912740189857575301128892105630080584412759834680227804744167703823413075975665088124941253511968357604377681`.

Additional details:

* `seed = 0x23AF000000000000`;
* `q - 1 = 2 * 3 * 13 * 23 * 1217 * r_{363}`;
* `q + 1 = 2^3 * 5 * 17 * r_{375}`.

## A.4 The `bign-curve512v1` curve

Parameters:

* `p = 2^{512} - 569`;
* `a = p - 3`;
* `b = 5693315954776639630120063851326436520321079941853637540614063305186549109521173166424386134606486352682464583832077941639002216168909012147763529108397200`;
* `q = 2^{512} - 34941104250934712071732195640491222284153110230636945247985077724188765679887`;
* `y_G = 8806852428097742705604110528553452385927484687246095572352640065245926924845204146464197290441971825763243615352431448274721410823777569490499978268765629`.

Additional details:

* `seed = 0xAE17020000000000`;
* `q - 1 = 2^4 * 23 * 79 * 767957 * 4433647 * 103529265929 * r_{419}`;
* `q + 1 = 2 * 3^2 * 5 * 19 * 13997 * 93740551 * 20778982613 * r_{427}`.

# ASN.1 definitions {#ASN1}

## Identifiers

Algorithms, protocols, elliptic curves and other objects of this specification
are assigned ASN.1 object identifiers presented below using the following
conventions:

* for a `key-dependent` Belt algorithm, its name has a 3-digit suffix
  specifying the key length: 128, 192 or 256;
* for a Belt digital signature algorithm, the object identifier specifies the
  respective hashing algorithm (see the description of the public parameters
  of `bign-sign`):
  - `belt-with-hbelt`: a combination of `bign-sign` and `belt-hash`;
  - `belt-with-hspec`: a different hashing algorithm is used, its OID becomes
    an additional parameter.

The identifiers are defined as follows:

       stb OBJECT IDENTIFIER ::= {iso(1) member-body(2) by(112) 0 2 0}

       belt OBJECT IDENTIFIER ::= {stb 34 101 31}
       bign OBJECT IDENTIFIER ::= {stb 34 101 45}
       bake OBJECT IDENTIFIER ::= {stb 34 101 66}

       belt-block128 OBJECT IDENTIFIER ::= {belt 3}
       belt-block192 OBJECT IDENTIFIER ::= {belt 4}
       belt-block256 OBJECT IDENTIFIER ::= {belt 5}
       belt-wblock128 OBJECT IDENTIFIER ::= {belt 6}
       belt-wblock192 OBJECT IDENTIFIER ::= {belt 7}
       belt-wblock256 OBJECT IDENTIFIER ::= {belt 8}
       belt-compress OBJECT IDENTIFIER ::= {belt 9}
       belt-ecb128 OBJECT IDENTIFIER ::= {belt 11}
       belt-ecb192 OBJECT IDENTIFIER ::= {belt 12}
       belt-ecb256 OBJECT IDENTIFIER ::= {belt 13}
       belt-cbc128 OBJECT IDENTIFIER ::= {belt 21}
       belt-cbc192 OBJECT IDENTIFIER ::= {belt 22}
       belt-cbc256 OBJECT IDENTIFIER ::= {belt 23}
       belt-cfb128 OBJECT IDENTIFIER ::= {belt 31}
       belt-cfb192 OBJECT IDENTIFIER ::= {belt 32}
       belt-cfb256 OBJECT IDENTIFIER ::= {belt 33}
       belt-ctr128 OBJECT IDENTIFIER ::= {belt 41}
       belt-ctr192 OBJECT IDENTIFIER ::= {belt 42}
       belt-ctr256 OBJECT IDENTIFIER ::= {belt 43}
       belt-mac128 OBJECT IDENTIFIER ::= {belt 51}
       belt-mac192 OBJECT IDENTIFIER ::= {belt 52}
       belt-mac256 OBJECT IDENTIFIER ::= {belt 53}
       belt-dwp128 OBJECT IDENTIFIER ::= {belt 61}
       belt-dwp192 OBJECT IDENTIFIER ::= {belt 62}
       belt-dwp256 OBJECT IDENTIFIER ::= {belt 63}
       belt-che128 OBJECT IDENTIFIER ::= {belt 64}
       belt-che192 OBJECT IDENTIFIER ::= {belt 65}
       belt-che256 OBJECT IDENTIFIER ::= {belt 66}
       belt-kwp128 OBJECT IDENTIFIER ::= {belt 71}
       belt-kwp192 OBJECT IDENTIFIER ::= {belt 72}
       belt-kwp256 OBJECT IDENTIFIER ::= {belt 73}
       belt-hash OBJECT IDENTIFIER ::= {belt 81}
       belt-keyexpand OBJECT IDENTIFIER ::= {belt 91}
       belt-keyrep OBJECT IDENTIFIER ::= {belt 101}

       bign-with-hspec OBJECT IDENTIFIER ::= {bign 11}
       bign-with-hbelt OBJECT IDENTIFIER ::= {bign 12}
       bign-genkeypair OBJECT IDENTIFIER ::= {bign 31}
       bign-valpubkey OBJECT IDENTIFIER ::= {bign 32}
       bign-keyt OBJECT IDENTIFIER ::= {bign 41}
       bign-genk OBJECT IDENTIFIER ::= {bign 61}
       bign-keys OBJECT IDENTIFIER ::= {bign keys(2)}
       bign-pubkey OBJECT IDENTIFIER ::= {bign-keys 1}
       bign-curves OBJECT IDENTIFIER ::= {bign curves(3)}
       bign-curve256v1 OBJECT IDENTIFIER ::= {bign-curves 1}
       bign-curve384v1 OBJECT IDENTIFIER ::= {bign-curves 2}
       bign-curve512v1 OBJECT IDENTIFIER ::= {bign-curves 3}
       bign-fields OBJECT IDENTIFIER ::= {bign fields(4)}
       bign-primefield OBJECT IDENTIFIER ::= {bign-fields prime(1)}

       bake-bmqv OBJECT IDENTIFIER ::= {bake 11}
       bake-bsts OBJECT IDENTIFIER ::= {bake 12}
       bake-bpace OBJECT IDENTIFIER ::= {bake 21}
       bake-kdf OBJECT IDENTIFIER ::= {bake 101}
       bake-swu OBJECT IDENTIFIER ::= {bake 201}
       bake-keys OBJECT IDENTIFIER ::= {bake keys(2)}
       bake-pubkey OBJECT IDENTIFIER ::= {bake-keys 1}

## Elliptic curve parameters

Elliptic curve parameters are described by the following data structure:

       DomainParameters ::= CHOICE {
         specified  ECParameters,
         named      OBJECT IDENTIFIER,
         implicit   NULL
       }.

The components of `DomainParameters` are interpreted as follows:

* `specified`: explicitly given numerical parameters;
* `named`: recommended parameters defined in {{CURVES}} and specified by an
  object identifier;
* `implicit`: inherited parameters from an external source (e.g., a certificate
  authority).

Explicit parameters `(p, a, b, q, y_G)` corresponding to a security level
`l in {128, 192, 256}` are described by the following data structures:

       ECParameters ::= SEQUENCE {
         version  INTEGER {ecpVer1(1)} (ecpVer1),
         fieldID  FieldID,
         curve    Curve,
         base     OCTET STRING (SIZE(32|48|64)),
         order    INTEGER,
         cofactor INTEGER (1) OPTIONAL
       };

       FieldID ::= SEQUENCE {
         fieldType   OBJECT IDENTIFIER (bign-primefield),
         parameters  INTEGER
       };

       Curve ::= SEQUENCE {
         a     OCTET STRING (SIZE(32|48|64)),
         b     OCTET STRING (SIZE(32|48|64)),
         seed  BIT STRING (SIZE(64))
       }.

The fields have the following meaning:

* `FieldId.parameters` stores the prime field base `p`. The bit length of `p`
  implicitly defines the security level `l`;
* `Curve.a` stores `<a>_{2*l}`;
* `Curve.b` stores `<b>_{2*l}`;
* `ECParameters.order` stores `q`;
* `ECParameters.base` stores `<y_G>_{2*l}`;
* `Curve.seed` stores the auxiliary parameter `seed` used to generate the curve.

## Public keys

At a security level `l`, the public key `Q` is stored as `<Q>_{4*l}`. It is
described by the following data structure:

       PublicKey ::= BIT STRING (SIZE(512|768|1024)).

In the X.509 public key certificates, the public key is described by the
following data structures:

       SubjectPublicKeyInfo ::= SEQUENCE {
         algorithm         AlgorithmIdentifier,
         subjectPublicKey  PublicKey
       };

       AlgorithmIdentifier ::= SEQUENCE {
         algorithm   OBJECT IDENTIFIER,
         parameters  ANY DEFINED BY algorithm OPTIONAL
       }.

Here

* `AlgorithmIdentifier.algorithm` is equal to the identifier `bign-pubkey`;
* `AlgorithmIdentifier.parameters` has the type `ECParameters` and stores
  elliptic curve parameters;
* `SubjectPublicKeyInfo.subjectPublicKey` stores the public key itself.

# Quotas for Belt encryption keys {#QUOTAS}

The encryption algorithms `belt-cbc`, `belt-cfb`,  `belt-ctr`, `belt-dwp`,
`belt-che` remain secure as long as the quotas for the keys they use are met.
The quota for a key is the maximum amount of data that can be encrypted using
this key. The quota is defined as the maximum allowed number of 128-bit
ciphertext blocks. The final blocks (which may be incomplete) are counted as
complete blocks. In `belt-dwp` and `belt-che` algorithms, each authentication
tag is counted as a block.

Security of encryption algorithms is understood as follows: for an adversary,
it is hard to distinguish ciphertexts `Y` from random messages. I.e., the
adversary and an oracle are playing the following game: the adversary chooses
a plaintext `X` and a nonce `S` following the rules given in {{BELT.Objects}}.
The oracle responds with either:

* a real ciphertext `Y` calculated using a random key `K`;
* a random binary word of the same length;

with equal probabilities.

The goal of the adversary is to determine the origin of the oracle's response:
encryption or random generation.

The advantage `p` of the adversary is defined as `|1 - alpha - beta|`, where
`alpha` is the probability of classifying random data as encrypted and `beta`
is the probability of classifying ecrypted data as random.

We can state that the probability of success of any reasonable chosen plaintext
attack against the encryption algorithm is bounded from above by the maximum
advantage `p` taken over all adversaries. In particular, if `p` is small, then
it is difficult to extact any information related to the plaintext `X` from the
ciphertext `Y`, except for its length.

The quotas are derived in a security model where `belt-block` encryption with
the fixed key `K` is represented by a random permutation. {{QUOTAS1}} and
{{QUOTAS2}} list quotas such that the advantage `p` does not exceed the
thresholds `2^{-32}`, `2^{-48}` and `2^{-64}`, which determine the respective
security assurance levels: average, high and maximum.

| Level   | belt-cbc   | belt-cfb   | belt-ctr            |
|---------|------------|------------|---------------------|
| average | `2^{48}`   | `2^{48}`   | `2^{48} * sqrt(2/3)`|
| high    | `2^{40}`   | `2^{40}`   | `2^{40} * sqrt(2/3)`|
| maximum | `2^{32}`   | `2^{32}`   | `2^{32} * sqrt(2/3)`|
{: #QUOTAS1 title="Quotas for `belt-cbc`, `belt-cfb` and `belt-ctr` keys"}

| Level   | belt-dwp                     | belt-che                     |
|---------|------------------------------|------------------------------|
| average | `2^{48} * sqrt(2/(7*D + 7))` | `2^{48} * sqrt(2/(5*D + 7))` |
| high    | `2^{40} * sqrt(2/(7*D + 7))` | `2^{40} * sqrt(2/(5*D + 7))` |
| maximum | `2^{32} * sqrt(2/(7*D + 7))` | `2^{32} * sqrt(2/(5*D + 7))` |
{: #QUOTAS2 title="Quotas for `belt-dwp` and `belt-che` keys"}

The value `D` in the last table depends on a particular application. It is
calculated as the maximum block length of the concatenation made from `X`,
`I`, and the block `<|X|>_{64} || <|I|>_{64}` formed from their lengths.

Here `sqrt` denotes the square root.

Quotas are not defined for the keys used by the algorithm `belt-ecb` since it
doesn't use nonces.

It is not necessary to specify quotas when processing cryptographic keys and
other high-entropy data that cannot be manipulated by an adversary.

**Example**. Consider an application where data is processed in packets.
An encrypted packet consists of a header `I`, a nonce `S`, a ciphertext `Y`
that corresponds to a plaintext `X` and an authentication tag `T`. Let the
length of `I` (in octets) be `46` and the length of `X` (again in octets) not
exceed `1408`. Then

~~~
D = ceiling(46/16) + ceiling(1408/16) + 1 = 92.
~~~

Here the `ceiling` function rounds a real number up to the nearest integer.

If the algorithm `belt-dwp` is used, then the maximum security assurance
is achieved if the total number of blocks in `X` and `T` does not exceed

~~~
2^{32} * sqrt(2/(7*92 + 7)) approx 2^{27.8}.
~~~

# Generating the S-box `H` {#BELTH}

Let the S-box `H` be represented by the array `H[0], H[1], ..., H[255]`,
where `H[x] = H(<x>_8)`.

This array can be generated as follows:

1. `H[10] <- 0x00`, `H[11] <- 0x8E`.
2. For `x = 12, 13, ..., 10 + 256`:
   1. `t <- H[(x - 1) mod 256]`;
   2. for `i = 0, 1, ..., 116`:
      1. `t <- Clock(t)`;
   3. `H[x] <- t`.
3. Return `H`.

Нere for `t = t_1 t_2 ... t_8 in {0, 1}^8`, 
`Clock(t) =  (t_2 ^ t_3 ^ t_7 ^ t_8) t_1 t_2 ... t_7`.

# Test vectors {#TEST}

## Test vectors for Belt algorithms

### Test vectors for `belt-block`

~~~
X = BeltH(0, 16)
K = BeltH(128, 32)
Y = belt-block(X, K):
  0x69CCA1C93557C9E3D66BC3E0FA88FA6E
~~~

~~~
Y = BeltH(64, 16)
K = BeltH(160, 32)
X = belt-block-inv(Y, K):
  0x0DC5300600CAB840B38448E5E993F421
~~~

### Test vectors for `belt-wblock`

~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
Y = belt-wblock(X, K):
  0x49A38EE108D6C742E52B774F00A6EF98
    B106CBD13EA4FB0680323051BC04DF76
    E487B055C69BCF541176169F1DC9F6C8
~~~

~~~
X = BeltH(0, 47)
K = BeltH(128, 32)
Y = belt-wblock(X, K):
  0xF08EF22DCAA06C81FB12721974221CA7
    AB82C62856FCF2F9FCA006E019A28F16
    E5821A51F573594625DBAB8F6A5C94
~~~

~~~
Y = BeltH(64, 48)
K = BeltH(160, 32)
X = belt-wblock-inv(Y, K):
  0x92632EE0C21AD9E09A39343E5C07DAA4
    889B03F2E6847EB152EC99F7A4D9F154
    B5EF68D8E4A39E567153DE13D72254EE
~~~

~~~
Y = BeltH(64, 36)
K = BeltH(160, 32)
X = belt-wblock-inv(Y, K):
  0xDF3F882230BAAFFC92F0566032117231
    0E3CB2182681EF43102E67175E177BD7
    5E93E4E8
~~~

### Test vectors for `belt-compress`

~~~
X = BeltH(0, 64)
(S, Y) = belt-compress(X):
  0x46FE7425C9B181EB41DFEE3E72163D5A
  0xED2F5481D593F40D87FCE37D6BC1A2E1
    B7D1A2CC975C82D3C0497488C90D99D8
~~~

### Test vectors for `belt-ecb`

~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
Y = belt-ecb(X, K):
  0x69CCA1C93557C9E3D66BC3E0FA88FA6E
    5F23102EF109710775017F73806DA9DC
    46FB2ED2CE771F26DCB5E5D1569F9AB0
~~~

~~~
X = BeltH(0, 47)
K = BeltH(128, 32)
Y = belt-ecb(X, K):
  0x69CCA1C93557C9E3D66BC3E0FA88FA6E
    36F00CFED6D1CA1498C12798F4BEB207
    5F23102EF109710775017F73806DA9
~~~

~~~
Y = BeltH(64, 48)
K = BeltH(160, 32)
X = belt-ecb-inv(Y, K):
  0x0DC5300600CAB840B38448E5E993F421
    E55A239F2AB5C5D5FDB6E81B40938E2A
    54120CA3E6E19C7AD750FC3531DAEAB7
~~~

~~~
Y = BeltH(64, 36)
K = BeltH(160, 32)
X = belt-ecb-inv(Y, K):
  0x0DC5300600CAB840B38448E5E993F421
    5780A6E2B69EAFBB258726D7B6718523
    E55A239F
~~~

### Test vectors for `belt-cbc`
~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
S = BeltH(192, 16)
Y = belt-cbc(X, K, S):
  0x10116EFAE6AD58EE14852E11DA1B8A74
    5CF2480E8D03F1C19492E53ED3A70F60
    657C1EE8C0E0AE5B58388BF8A68E3309
~~~

~~~
X = BeltH(0, 40)
K = BeltH(128, 32)
S = BeltH(192, 16)
Y = belt-cbc(X, K, S):
  0x10116EFAE6AD58EE14852E11DA1B8A74
    6A9BBADCAF73F968F875DEDC0A44F6B1
    5CF2480E
~~~

~~~
Y = BeltH(64, 48)
K = BeltH(160, 32)
S = BeltH(208, 16)
X = belt-cbc-inv(Y, K, S):
  0x730894D6158E17CC1600185A8F411CAB
    0471FF85C83792398D8924EBD57D03DB
    95B97A9B7907E4B020960455E46176F8
~~~

~~~
Y = BeltH(64, 40)
K = BeltH(160, 32)
S = BeltH(208, 16)
X = belt-cbc-inv(Y, K, S):
  0x730894D6158E17CC1600185A8F411CAB
    B6AB7AF8541CF85755B8EA27239F08D2
    166646E4
~~~

### Test vectors for `belt-cfb`

~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
S = BeltH(192, 16)
Y = belt-cfb(X, K, S):
  0xC31E490A90EFA374626CC99E4B7B8540
    A6E48685464A5A06849C9CA769A1B0AE
    55C2CC5939303EC832DD2FE16C8E5A1B
~~~

~~~
Y = BeltH(64, 48)
K = BeltH(160, 32)
S = BeltH(208, 16)
X = belt-cfb-inv(Y, K, S):
  0xFA9D107A86F375EE65CD1DB881224BD0
    16AFF814938ED39B3361ABB0BF0851B6
    52244EB06842DD4C94AA4500774E40BB
~~~

### Test vectors for `belt-ctr`

~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
S = BeltH(192, 16)
Y = belt-ctr(Y, K, S):
  0x52C9AF96FF50F64435FC43DEF56BD797
    D5B5B1FF79FB41257AB9CDF6E63E81F8
    F00341473EAE409833622DE05213773A
~~~

~~~
Y = BeltH(64, 44)
K = BeltH(160, 32)
S = BeltH(208, 16)
X = belt-ctr-inv(Y, K, S):
  0xDF181ED008A20F43DCBBB93650DAD34B
    389CDEE5826D40E2D4BD80F49A93F5D2
    12F6333166456F169043CC5F
~~~

### Test vectors for `belt-mac`

~~~
X = BeltH(0, 13)
K = BeltH(128, 32)
Y = belt-mac(X, K):
  0x7260DA60138F96C9
~~~

~~~
X = BeltH(0, 48)
K = BeltH(128, 32)
Y = belt-mac(X, K):
  0x2DAB59771B4B16D0
~~~

### Test vectors for `belt-dwp`

~~~
X = BeltH(0, 16)
I = BeltH(16, 32)
K = BeltH(128, 32)
S = BeltH(192, 16)
(Y, T) = belt-dwp(X, I, K, S):
  0x52C9AF96FF50F64435FC43DEF56BD797
  0x3B2E0AEB2B91854B
~~~

~~~
Y = BeltH(64, 16)
I = BeltH(80, 32)
K = BeltH(160, 32)
S = BeltH(208, 16)
T = 0x6A2C2C94C4150DC0
X = belt-dwp-inv(Y, I, K, S, T):
  0xDF181ED008A20F43DCBBB93650DAD34B
~~~

### Test vectors for `belt-che`

~~~
X = BeltH(0, 15)
I = BeltH(16, 32)
K = BeltH(128, 32)
S = BeltH(192, 16)
(Y, T) = belt-che(X, I, K, S):
  0xBF3DAEAF5D18D2BCC30EA62D2E70A4
  0x548622B844123FF7
~~~

~~~
Y = BeltH(64, 20)
I = BeltH(80, 32)
K = BeltH(160, 32)
S = BeltH(208, 16)
T = 0x7D9D4F59D40D197D
X = belt-che-inv(Y, I, K, S, T):
  0x2BABF43EB37B5398A9068F31A3C758
    B762F44AA9
~~~

### Test vectors for `belt-kwp`

~~~
X = BeltH(0, 48)
I = BeltH(32, 16)
K = BeltH(128, 32)
Y = belt-kwp(X, I, K):
  0x49A38EE108D6C742E52B774F00A6EF98
    B106CBD13EA4FB0680323051BC04DF76
    E487B055C69BCF541176169F1DC9F6C8
~~~

~~~
Y = BeltH(64, 48)
I = 0xB5EF68D8E4A39E567153DE13D72254EE
K = BeltH(160, 32)
X = belt-kwp-inv(Y, I, K):
  0x92632EE0C21AD9E09A39343E5C07DAA4
    889B03F2E6847EB152EC99F7A4D9F154
~~~

### Test vectors for `belt-hash`

~~~
X = BeltH(0, 13)
Y = belt-hash(X):
  0xABEF9725D4C5A83597A367D14494CC25
    42F20F659DDFECC961A3EC550CBA8C75
~~~

~~~
X = BeltH(0, 32)
Y = belt-hash(X):
  0x749E4C3653AECE5E48DB4761227742EB
    6DBE13F4A80F7BEFF1A9CF8D10EE7786
~~~

~~~
X = BeltH(0, 48)
Y = belt-hash(X):
  0x9D02EE446FB6A29FE5C982D4B13AF9D3
    E90861BC4CEF27CF306BFB0B174A154A
~~~

### Test vectors for `belt-keyexpand`

~~~
X = BeltH(128, 16)
K = belt-keyexpand(X):
  0xE9DEE72C8F0C0FA62DDB49F46F739647
    E9DEE72C8F0C0FA62DDB49F46F739647
~~~

~~~
X = Belt(128, 24)
K = belt-keyexpand(X):
  0xE9DEE72C8F0C0FA62DDB49F46F739647
    06075316ED247A374B09A17E8450BF66
~~~

### Test vectors for `belt-keyrep`

~~~
X = BeltH(128, 32)
D = 0x010000000000000000000000
I = BeltH(32, 16)
Y = belt-keyrep(X, D, I, 128):
  0x6BBBC2336670D31AB83DAA90D52C0541
Y = belt-keyrep(X, D, I, 192):
  0x9A2532A18CBAF145398D5A95FEEA6C82
    5B9C197156A00275
Y = belt-keyrep(X, D, I, 256):
  0x76E166E6AB21256B6739397B672B8796
    14B81CF05955FC3AB09343A745C48F77
~~~

## Test vectors for Bign algorithms

### Settings

Test vectors are constructed using the settings given below.

* Elliptic curve parameters: `bign-curve256v1`.

* A private key `d`:

~~~
<d>_256 = 0x1F66B5B84B7339674533F0329C74F218
            34281FED0732429E0C79235FC273E269
~~~

* A public key `Q`:

~~~
<Q>_512 = 0xBD1A5650179D79E03FCEE49D4C2BD5DD
            F54CE46D0CF11E4FF87BF7A890857FD0
            7AC6A60361E8C8173491686D461B2826
            190C2EDA5909054A9AB84D2AB9D99A90
~~~

* A hashing algorithm `h` (for digital signature): `belt-hash` with
`OID(belt-hash) = 0x06092A7000020022651F511`.

### Test vectors for `bign-sign`

~~~
X = BeltH(0, 13)
H:
  0xABEF9725D4C5A83597A367D14494CC25
    42F20F659DDFECC961A3EC550CBA8C75
<k>_256:
  0x4C0E74B2CD5811AD21F23DE7E0FA742C
    3ED6EC483C461CE15C33A77AA308B7D2
<R>_512:
  0xCCEEF1A313A406649D15DA0A851D486A
    695B641B20611776252FFDCE39C71060
    7C9EA1F33C23D20DFCB8485A88BE6523
    A28ECC3215B47FA289D6C9BE1CE837C0
S_0:
  0xE36B7F0377AE4C524027C387FADF1B20
S_1:
  0xCE72F1530B71F2B5FD3A8C584FE2E1AE
    D20082E30C8AF65011F4FB54649DFD3D
S = bign-sign(X, d):
  0xE36B7F0377AE4C524027C387FADF1B20
    CE72F1530B71F2B5FD3A8C584FE2E1AE
    D20082E30C8AF65011F4FB54649DFD3D
~~~

### Test vectors for `bign-vfy`

~~~
X = BeltH(0, 48)
S = 0x47A63C8B9C936E94B5FAB3D9CBD78366
      290F3210E163EEC8DB4E921E8479D413
      8F112CC23E6DCE65EC5FF21DF4231C28
S_0:
  0x47A63C8B9C936E94B5FAB3D9CBD78366
S_1:
  0x290F3210E163EEC8DB4E921E8479D413
    8F112CC23E6DCE65EC5FF21DF4231C28
H:
  0x9D02EE446FB6A29FE5C982D4B13AF9D3
    E90861BC4CEF27CF306BFB0B174A154A
<R>_512:
  0x1D5A382B962D4ED06193258CA6DE535D
    8FD7FACB853171E932EF93B5EE800120
    03DBB7B5BD07036380BAFA47FCA7E6CA
    3F179EDDD1AE5086647909183628EDDC
t:
  0x47A63C8B9C936E94B5FAB3D9CBD78366
bign-vfy(X, S, Q):
  1
~~~

### Test vectors for `bign-keyt`

~~~
X = BeltH(0, 18)
I = 0x5BE3D61217B96181FE6786AD716B890B
<k>_256:
  0x0F51D91347617C20BD4AB07AEF4F26A1
    AD1362A8F9A3D42FBE1B8E6F1C88AAD5
<R>_512:
  0x9B4EA669DABDF100A7D4B6E6EB76EE52
    51912531F426750AAC8A9DBB51C54D8D
    6AB7DBF15FCBD768EE68A173F7B236EF
    C15A01E2AA6CD1FE98B947DA7B38A2A0
K:
  0x11B3A63983BCCB6D32C5943F66F01D4C
    EA8CEE35E4A6AE98B1407C53674317AC
Y = bign-keyt(X, d):
  0x9B4EA669DABDF100A7D4B6E6EB76EE52
    51912531F426750AAC8A9DBB51C54D8D
    EB9289B50A46952D0531861E45A8814B
    008FDC65DE9FF1FA2A1F16B6A280E957
    A814
~~~

### Test vectors for `bign-keyt-inv`

~~~
Y = 0x4856093A0F6C13015FC8E15F1B23A762
      02D2F4BA6E5EC52B78658477F6486DE6
      87AFAEEA0EF7BC1326A7DCE7A10BA10E
      3F91C0126044B22267BF30BD6F1DA29E
      0647CF39C1D59A56BB0194E0F4F8A2BB
I = 0xE12BDC1AE28257EC703FCCF095EE8DF1
<k>_256:
  0x0F51D91347617C20BD4AB07AEF4F26A1
    AD1362A8F9A3D42FBE1B8E6F1C88AAD5
<R>_256:
  0x4856093A0F6C13015FC8E15F1B23A762
    02D2F4BA6E5EC52B78658477F6486DE6
Y_1:
  0x87AFAEEA0EF7BC1326A7DCE7A10BA10E
    3F91C0126044B22267BF30BD6F1DA29E
    0647CF39C1D59A56BB0194E0F4F8A2BB
<y_R>_256:
  0xDA4FE935574DA2F0117AFE25971DFD62
    9D985CE9E4F1052C664456862C83CD37
K:
  0x3E2D491538A58FA5108CF80985222670
    661794AB2423E4109E785A22D1529BC6
X = bign-keyt-inv(Y, I, d):
  BeltH(0, 32)
~~~

### Test vectors for `bign-genk`

~~~
H = 0xABEF9725D4C5A83597A367D14494CC25
      42F20F659DDFECC961A3EC550CBA8C75
t = NULL
K = 0xD61E3A910550E3BCAD5BF4F526FB8DAA
      DEA9C132E0BAEE03169DF4DF9BD6C20C
<k = bign-genk(d, H)>_256:
  0x829614D8411DBBC4E1F2471A40045864
    40FD8C9553FAB6A1A45CE417AE97111E
~~~

~~~
H = 0x9D02EE446FB6A29FE5C982D4B13AF9D3
      E90861BC4CEF27CF306BFB0B174A154A
t = 0xBE32971343FC9A48A02A885F194B09A1
      7ECDA4D01544AF
K = 0xAE44316332A85C3B9F6B31EEEADFF088
      D30FE507021AC86A3EC8E0874ED33648
<k = bign-genk(d, H)>_256:
  0x7ADC8713283EBFA547A2AD9CDFB245AE
    0F7B968DF0F91CB785D1F932A3583107
~~~

## Test vectors for Bake protocols

### Settings

Test vectors are constructed using the settings given below.

* Elliptic curve parameters: `bign-curve256v1`.

* Identifiers:

~~~
Id_A = 0x416C696365
Id_B = 0x426F62
~~~

* Private keys `d_A` and `d_B`:

~~~
<d_A>_256 = 0x1F66B5B84B7339674533F0329C74F218
              34281FED0732429E0C79235FC273E269
<d_B>_256 = 0x4C0E74B2CD5811AD21F23DE7E0FA742C
              3ED6EC483C461CE15C33A77AA308B7D2
~~~

* Public keys `Q_A` and `Q_B`:

~~~
<Q_A>_512 = 0xBD1A5650179D79E03FCEE49D4C2BD5DD
              F54CE46D0CF11E4FF87BF7A890857FD0
              7AC6A60361E8C8173491686D461B2826
              190C2EDA5909054A9AB84D2AB9D99A90
<Q_B>_512 = 0xCCEEF1A313A406649D15DA0A851D486A
              695B641B20611776252FFDCE39C71060
              7C9EA1F33C23D20DFCB8485A88BE6523
              A28ECC3215B47FA289D6C9BE1CE837C0
~~~

### Test vectors for `bake-bmqv`

~~~
<u_B>_256:
  0x0F51D91347617C20BD4AB07AEF4F26A1
    AD1362A8F9A3D42FBE1B8E6F1C88AAD5
<V_B>_512:
  0x9B4EA669DABDF100A7D4B6E6EB76EE52
    51912531F426750AAC8A9DBB51C54D8D
    6AB7DBF15FCBD768EE68A173F7B236EF
    C15A01E2AA6CD1FE98B947DA7B38A2A0
<u_A>_256:
  0x0A4E8298BE0839E46F19409F637F4415
    572251DD0D39284F0F0390D93BBCE9EC
<V_A>_512:
  0x1D5A382B962D4ED06193258CA6DE535D
    8FD7FACB853171E932EF93B5EE800120
    03DBB7B5BD07036380BAFA47FCA7E6CA
    3F179EDDD1AE5086647909183628EDDC
t:
  0xBD46F58ADE7C4DF9826D32ABA9113428
<s_A>_256:
  0xAB4EB3A6D867C86152E61B647F1A32D9
    93A7768F79361F750AE7C7A65CD9A233
<K>_512:
  0x7FF3A0DACDFECB3CD25F4D3C334CCCB3
    34C71FF71E2247DD0688FA62DF4C5920
    728CB85598DA04B48D85D32D0CDCCD92
    3D88E8449BAA5065B4E4D1CBEEE31D35
K_0:
  0xC6F86D0E468D5EF1A9955B2EE0CF0581
    050C81D1B47727092408E863C7EEB48C
K_1:
  0xE95BA3F645C58288E8A1B37C10ADD336
    DB8BD7F675F94963139769F2E260C6A9
T_A:
  0x413B7E181BAFB337
<s_B>_256:
  0xB60996332B62DDB1354EC03DA949B528
    969E6CA6D8848C94013B9CF6FF42AEED
T_B:
  0xB800A2033AC7591B
~~~

### Test vectors for `bake-bsts`

~~~
<u_B>_256:
  0x0F51D91347617C20BD4AB07AEF4F26A1
    AD1362A8F9A3D42FBE1B8E6F1C88AAD5
<V_B>_512:
  0x9B4EA669DABDF100A7D4B6E6EB76EE52
    51912531F426750AAC8A9DBB51C54D8D
    6AB7DBF15FCBD768EE68A173F7B236EF
    C15A01E2AA6CD1FE98B947DA7B38A2A0
<u_A>_256:
  0x0A4E8298BE0839E46F19409F637F4415
    572251DD0D39284F0F0390D93BBCE9EC
<V_A>_512:
  0x1D5A382B962D4ED06193258CA6DE535D
    8FD7FACB853171E932EF93B5EE800120
    03DBB7B5BD07036380BAFA47FCA7E6CA
    3F179EDDD1AE5086647909183628EDDC
<K>_512:
  0xC91218504B2F10C8B307B3F85A292930
    8E48F33451D2810AAD788DE8CA4C7347
    7693216730B95FD3C1439D6CB99A1A0B
    2898FC563558C8F518E235B9D7441A6E
K_0:
  0x78EF2C56BD6DA2116BB5BEE80CEE5C05
    394E7609183CF7F76DF0C2DCFB25C4AD
K_1:
  0xF02580E95C1E89BD9E743C02716E3E31
    FA429298AE0FD1FE2BBA1B5702E51B9D
K_2:
  0x412836224A0C09641F3C3B888C7804FA
    32B94A62B5CB0066518409F969191776
t:
  0xBD46F58ADE7C4DF9826D32ABA9113428
<s_A>_256:
  0xAB4EB3A6D867C86152E61B647F1A32D9
    93A7768F79361F750AE7C7A65CD9A233
Y_A:
  0xA994115F297D2FAD342A0AF54FCDA66E
    1E6A30FE966662C43C2A73AFA3CADF69
    47344287CB200795616458678B76BA61
    924AD05D80BB81F53F8D5C4E0EF55EBD
    AFA674D7ECD74CB0609DE12BC0463670
    64059F011607DD18624074901F1C5A40
    94C006559F
T_A:
  0x1306D68200087987
<s_B>_256:
  0xB60996332B62DDB1354EC03DA949B528
    969E6CA6D8848C94013B9CF6FF42AEED
Y_B:
  0x6D45B2E76AF24422ADC6D5D7A3CFA37F
    DCB52F7E440222F1AACECB98BDED357B
    BD459DF0A3EE7A3EAFE0199CA5C4C072
    7C33909E4C322216F6F53E383A3727D8
    34B5D4F5C977FC3B7EBA6DCA55C0F1A5
    69BE3CD3464B13C388D0DAC3E6A82F9D
    2EF3D6
T_B:
  0xCA7A5BAC4EB2910E
~~~

### Test vectors for `bake-bpace`

~~~
P = 0x38303836
R_B:
  0x0F51D91347617C20BD4AB07AEF4F26A1
K_2:
  0x3292E21E6CD50D272532713BA52570A4
    C996319E2436B3857DB0ACB45660F4EB
Y_B:
  0x991E81690B4C687C86BFD11CEBDA2421
R_A:
  0xAD1362A8F9A3D42FBE1B8E6F1C88AAD5
Y_A:
  0xCE41B54DC13A28BDF74CEBD190881802
<W>_512:
  0x014417D3355557317D2E2AB6D0875487
    8D19E8D97B71FDC95DBB2A9B894D16D7
    7704A0B5CAA9CDA10791E4760671E105
    0DDEAB7083A7458447866ADB01473810
<u_A>_256:
  0x0A4E8298BE0839E46F19409F637F4415
    572251DD0D39284F0F0390D93BBCE9EC
<V_A>_512:
  0x6B13ACBB086FB87618BCC2EF20A3FA89
    475654CB367E670A2441730B24B8AB31
    8209C81C9640C47A77B28E90AB9211A1
    DF21DE878191C314061E347C5125244F
<u_B>_256:
  0xF81B29D571F6452FF8B2B97F57E18A58
    BC946FEE45EAB32B06FCAC23A33F422B
<V_B>_512:
  0xCD3D6487DC4EEB23456978186A069C71
    375D75C2DF198BAD1E61EEA0DBBFF737
    3D1D9ED17A7AD460AA420FB11952D580
    78BC1CC9F408F2E258FDE97F22A44C6F
<K>_512:
  0x723356E335ED70620FFB1842752092C3
    2603EB666040920587D800575BECFC42
    0C4B4C9B4AEB51D36FE2EDEB1369CE39
    676CE5440E29916C97FBA4F3ED6A31BD
K_0:
  0xDAC4D8F411F9C523D28BBAAB32A5270E
    4DFA1F0F757EF8E0F30AF08FBDE1E7F4
K_1:
  0x54AC058284D679CF4C47D3D72651F3E4
    EF0D61D1D0ED5BAF8FF30B8924E599D8
T_B:
  0x28FD4859D78BA971
T_A:
  0x5D93FD9A7CB863AA
~~~
