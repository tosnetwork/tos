# The shielded pool's Groth16 ceremony

Every proof this branch has ever produced verifies under a key drawn from the
seed `tos-shielded-pool-v1-devkeys-001`. The seed is in the source, so the
toxic waste is public, so **anyone can forge a proof under that key** and mint
themselves a note. Section 17 and section 20 say so, the fixture says so in its
own `warning` field, and it is the single reason this pool cannot hold money
today.

Replacing it needs a two-phase trusted setup. Both phases now exist in code:
phase 1 is a published ceremony's transcript, sliced and checked, and phase 2
is a multi-party computation written here. This document is what each part
establishes, what it does not, and what still has to come from people rather
than from software.

## What has to be produced

One thing, in the end: **1,248 bytes**. Section 10.1's verifying key, which
goes into the genesis configuration store, which fixes the state hash, which
fixes the deployment address. Everything else a ceremony generates — the
proving key, the transcripts, the attestations — exists to make those bytes
trustworthy.

## Phase 1: reused, sliced, and checked

Phase 1 is circuit-independent, so it is not ours to run — it is ours to
*choose*, and the choice is a **custody** decision rather than a technical one.
Whichever ceremony is picked, the deployment inherits that ceremony's
participants and nothing else. So the transcript is a described thing in
`layout.rs` with its provenance attached, not a constant somebody once typed,
and the provenance record beside every fetched slice names it in its first
field.

### Which ceremony, and why

Two published BLS12-381 powers-of-tau are large enough:

| | Zcash Sapling | Filecoin |
|---|---|---|
| degree | 2^21 — 64× this circuit | 2^27 |
| when | 2017–2018 | end of 2019 |
| provenance | **the canonical BLS12-381 ceremony**; later ones reference it | its own ceremony, *not* a continuation of Zcash's — Zcash's 2^21 was too small for Filecoin's hundred-million-gate circuits |
| attested | 87 named humans + a public random beacon, of an 89-round chain | not examined here |
| an 18 MB slice takes | **seconds** (Internet Archive) | ~25 minutes (IPFS gateway) |

**The default is Zcash.** Better provenance, far better availability, and its
contribution chain turned out to be *auditable from published material* — two
links of it were recomputed against PGP signatures from 2017 before it was made
the default. Filecoin's only advantage is headroom this circuit does not need;
it is kept as an alternative, because two independent sources hedge
availability and one of them has already lost its original host.

Neither is preferred by the code. `--transcript filecoin` switches, and the
tests pin both ceremonies' artifacts so that changing the default means moving
a pin rather than discovering later that nothing was checking.

The full audit, including the 89-vs-88-vs-87 round count and the two hash
computations that resolve it, is in
`memo/privacy/measurements/zcash-transcript-audit-20260921/`.

**This circuit needs 2^15.** Not chosen — measured:

```
constraints 18,107   instance 19   witness 18,215
QAP degree = constraints + instance = 18,126
          -> domain 2^15 = 32,768             (14,642 to spare)
```

`constraints + instance_variables`, not `max(constraints, variables)`. The
setup gives every instance variable a Lagrange coefficient of its own at index
`num_constraints + i` — those are the input-consistency rows — so the domain
has to reach past the constraints by exactly the number of inputs. This
document said 18,234 and 14,534 until the formula was checked against a key
`ark-groth16` actually built; both round to 2^15, so the slice was right
either way, but the headroom was not, and the headroom is the number somebody
adding constraints reads.

`tools/shielded-pool-ceremony/tests/degree.rs` holds this against the circuit
on every run, and it is a gate rather than a note: every byte offset below is a
function of the exponent, so a circuit that grew past 32,768 would make an
already-fetched slice *the wrong bytes* rather than too few of them. One of
those tests builds a real key and reads the domain back out of it; another
pins the formula on a shape where the two candidates disagree, because for
*this* circuit they do not, and a test that cannot tell them apart is not
evidence about which is right.

### Eighteen megabytes, and where they sit in each file

The accumulator stores five sections, each in ascending power order, so a
degree-2^15 SRS is a prefix of every section rather than a prefix of the file.
Both ceremonies were fetched on 2026-09-21; the sections are the same shape and
the same size either way, and only the offsets differ.

**Zcash** — the default. The accumulator is the last of 89 records, so every
offset is deep in the file. Slice
`1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e`:

| section | points | bytes | offset | sha256 |
|---|---:|---:|---:|---|
| `tau_g1` | 65,535 | 6,291,360 | 106,300,550,400 | `b228baf1…47d9d9` |
| `tau_g2` | 32,768 | 6,291,456 | 106,703,203,488 | `01aafa19…322585` |
| `alpha_tau_g1` | 32,768 | 3,145,728 | 107,105,856,672 | `0377104a…91b832` |
| `beta_tau_g1` | 32,768 | 3,145,728 | 107,307,183,264 | `4e36cc73…696ece` |
| `beta_g2` | 1 | 192 | 107,508,509,856 | `7137a823…75ec73` |

**Filecoin** — a challenge file, so the accumulator starts 64 bytes in. Slice
`d161614630b0504bd02075a9f57e7ca18d24f0c7c911c5cda5a686e91b8ced75`:

| section | points | bytes | offset | sha256 |
|---|---:|---:|---:|---|
| `tau_g1` | 65,535 | 6,291,360 | 64 | `5fe833e9…22e602` |
| `tau_g2` | 32,768 | 6,291,456 | 25,769,803,744 | `97f86b31…bdb502` |
| `alpha_tau_g1` | 32,768 | 3,145,728 | 51,539,607,520 | `bb92e0d5…b71491` |
| `beta_tau_g1` | 32,768 | 3,145,728 | 64,424,509,408 | `fc3dae17…92c617` |
| `beta_g2` | 1 | 192 | 77,309,411,296 | `605833eb…f1d3ba` |

Anyone holding a transcript can reproduce its slice with five reads, because
the slice file is those ranges end to end with nothing added. The full hashes
are in each fetch's provenance record and pinned in
`tools/shielded-pool-ceremony/tests/the_real_slice.rs`.

### Where the artifacts live

```
artifacts/phase1/phase1-zcash-2m15.bin      18,874,464   1bfd7acd…   ← stored
artifacts/phase1/phase1-zcash-2m15.json          1.6 KB              ← stored
artifacts/phase1/phase1-filecoin-2m15.json       1.6 KB              ← stored
artifacts/phase1/phase1-filecoin-2m15.bin   18,874,464   d1616146…   fetch on demand
```

**The default ceremony's bytes are in the repository.** Eighteen megabytes is a
real cost and a smaller one than it first sounds: this repository already
carries a 27 MB source file and two of 19.5 MB, against a history of 593 MB.

What it buys is not convenience. **A deployment's entire custody argument rests
on those bytes**, and until they were committed they existed in exactly one
place in the world that we do not control. Zcash's original S3 host is already
gone — both the torrents and the per-response files return 404 — so the Internet
Archive copy is the only one left. Storing them is the difference between
"reproducible, as long as one archive survives" and "reproducible".

**Filecoin's bytes are not stored, and that is the point of storing Zcash's.**
The reason to carry a second ceremony was to hedge availability, and committing
the default's slice is a better hedge than a second remote host. What is kept
is its *descriptor and its record* — forty lines and 1.6 KB — so that
`--transcript filecoin` still fetches and verifies, the code still has two
ceremonies to be held to rather than one it might quietly assume, and the
check that refuses one ceremony's slice under the other's name still has
something to refuse. Eighteen megabytes for a contingency that a fetch answers
in twenty-five minutes is not a trade worth making.

The records are 1.6 KB each and carry the ceremony's name, the ranges by offset
and length, each section's SHA-256, the slice's own, and the custody sentence.
They are what lets bytes obtained by *any* route — a mirror, a torrent, a
colleague's disk, this repository — be checked rather than trusted.

A slice can still be re-fetched and the result must be identical; that is what
the hashes are for. Zcash's takes seconds, Filecoin's about twenty-five minutes
through its IPFS gateway.

The reference string stays out, and the reasoning is not the same. It is seven
seconds of arithmetic from a slice that is now in the repository, so storing it
would add a derived copy that can go stale while removing no dependency on
anybody.

**The tests against the real slices now run by default**, which is what storing
the bytes actually bought. While they had to be fetched the choice was between
failing for everyone who had not fetched them and skipping quietly — and a test
that passes while doing nothing is the failure this repository's `CLAUDE.md`
opens with — so they were `#[ignore]`d and hardly ever ran. The strongest
evidence here now runs on every invocation, for about twenty seconds.

Getting those offsets wrong is the worst error available here: the bytes would
parse, the points would be on the curve and in the right subgroup, and
verification would fail with nothing to say about why. Two independent facts
guard it.

**The total.** The layout implies a file size and the server publishes one, and
they agree to the byte: 77,309,411,488. That pins the element counts, the
uncompressed widths and the 64-byte transcript-digest prefix.

**The order.** A total is the same whatever order the sections are in, so it
pins nothing about which comes first. The order is the one
`Accumulator::serialize` writes; what actually catches an order mistake is the
verification, because sections read in the wrong order are not powers of the
same tau and no pairing check holds. There is a test for exactly that.

### What the verification establishes

`verify-phase1-slice` parses the slice — blst deciding what a point is,
including the **subgroup** check a hostile transcript would be trying to get
past — and then runs the checks `Accumulator::verify` runs, restricted to a
prefix, which is sound because each is a statement about consecutive elements:

* the zeroth power is the generator, in both groups;
* the tau in G1 is the tau in G2;
* alpha and beta advance by that same tau;
* the beta in G1 is the beta in G2;
* and every remaining power, batched into one pairing check per section with
  randomness drawn from the operating system — not from the slice, because
  scalars a malicious transcript could predict are scalars it could cancel
  against.

Nine tests build strings broken one way at a time and require the check aimed
at each to catch it, including the two that every other check passes: a string
of consistent powers of the *wrong generator*, and alpha and beta sections
swapped.

**And it has been run against the real slice, both ways.** The 18 MB fetched
from the transcript verifies: 131,839 points, all in the prime-order subgroup,
every ratio holding. Then two genuine powers from that same transcript,
`tau_g1[40000]` and `tau_g1[40001]`, were swapped — every point still valid,
every point still in the subgroup, the file still hashing to its record — and
it was refused:

```
REFUSED: structure: the G1 powers of tau are not consecutive powers of one tau
```

A single flipped bit is caught earlier and more cheaply, by `blst` with
`BLST_POINT_NOT_ON_CURVE`, which is why the swap is the interesting case: it is
the one a corrupted or hostile transcript could survive everything but the
pairing checks with.

### What it does not establish

**Nothing about who knows tau.** That property comes from the contribution
chain — many participants from 2017 on, each multiplying in a secret and
proving they did — and re-verifying it means replaying every response in the
transcript, not reading the final accumulator. A slice cannot carry it and no
amount of pairing arithmetic on the slice will produce it.

So a deployment relies on two different things and should say so: **structure
checked here, custody inherited from the published ceremony.** The 64-byte
digest at the head of the challenge file is recorded in the slice's provenance
so a deployment can be held against that ceremony's attestations.

```
transcript digest 6e3f4b98e6c205d0efa5abc917dd03e28864016df380936fa4e9865595c5d698
                  63eff93e8badf8e6b8c8cbfd5ab3a415ef7ba50b86e124bd9bfcd3f9aab67124
```

## Phase 1.5: the basis change nobody mentions

A verified slice is not yet something a setup can use, and the step between is
easy to miss because it has no ceremony around it.

The transcript stores the **monomial** basis: `τ^0, τ^1, τ^2, …` in the
exponent. Groth16's setup needs the **Lagrange** basis over the evaluation
domain — `L_0(τ), L_1(τ), …` where `L_j` is the polynomial that is 1 at `ω^j`
and 0 at every other root of unity. It needs that because the QAP polynomials
`A_i, B_i, C_i` are defined by their values on the domain, so `A_i(τ)` is a
combination of `L_j(τ)` and not of `τ^j`.

The two are related by an inverse DFT, in the exponent:

```
L_j(X) = (1/n) · Σ_i ω^(-ji) · X^i        so        L_j(τ)·G = (1/n) · Σ_i ω^(-ji) · (τ^i·G)
```

which is exactly `ifft` applied to the group elements. Filecoin runs this as a
separate stage they call phase 1.5, with a `create_lagrange` binary, and
publish the results as `phase1radix2m{k}`.

**Those files do not help us.** Only `phase1radix2m19` and `phase1radix2m27`
are published, and a Lagrange basis is tied to one evaluation domain: the
2^19 basis is not a prefix of the 2^15 one, it is a different set of
polynomials over a different set of roots. So this circuit's 2^15 basis has to
be computed here.

That is done, in `tools/shielded-pool-ceremony/src/lagrange.rs`. It is a good
deal safer than what follows it, and worth saying why: **the transform has no
secrets.** It is a fixed linear map, so its output can be checked against its
input rather than trusted, and four independent checks do exactly that.

The same stage also builds the **`h` query**, the other thing the monomial
basis is needed for. Groth16's prover divides by the vanishing polynomial
`t(X) = X^n − 1`, so the setup needs `τ^i·t(τ)` for `i` up to `n−2` — which is

```
τ^i·t(τ) = τ^(i+n) − τ^i
```

and that is the only reason the transcript's G1 section runs to `2n−2` rather
than `n−1`. It is also the reason the slice's longest range is the one it is.

### Checking a transform that has no secrets

Four checks, each able to fail, none of them a restatement of the arithmetic:

* **Against the definition, with τ known.** A slice built from a chosen τ makes
  `L_j(τ)` computable in closed form — `ω^j(τ^n − 1) / (n(τ − ω^j))` — with no
  FFT anywhere. Every output element is required to equal it. This is the test
  that would catch a wrong domain, a forward transform where an inverse was
  meant, or a missing `1/n`.
* **The basis sums to one.** `Σ_j L_j(X) = 1` identically, so `Σ_j L_j(τ)·G`
  must be exactly the generator. Cheap, and independent of everything else.
* **A random polynomial, evaluated two ways.** Pick values `e_j` on the domain.
  Then `Σ_j e_j·L_j(τ)` over the Lagrange output must equal `Σ_i c_i·τ^i` over
  the monomial input, where `c = ifft(e)` in the field. Two different routes
  from the same polynomial to the same point.
* **The `h` query advances by τ**, batched into one pairing check, the same way
  the phase-1 powers are.

And the pieces are tied to each other: `e(L_j(τ)·G1, G2) = e(G1, L_j(τ)·G2)`
batched over the whole vector, so the two groups carry the same basis.

Eight tests break a constructed transform one way at a time. The sharpest is
two basis elements swapped **in both groups at once**: the sum is unchanged, so
the identity check passes; the groups still agree with each other, so the
pairing check passes; every point is genuine. Only going back to the powers it
was built from sees it. A swap in G1 alone is the easier case — the pairing
check catches that one first.

### Done, on the real slice

```
n = 32,768 basis points a group, 32,767 in the h query
transform  5.5 s        verify  1.4 s
reference string b30791cf1925a9184e90d9088acbc8299ae172fd3ef9958d892065368325baba
```

Seven seconds, so this is a step in the ceremony rather than an artifact to
store: the SRS is derived from the slice whenever it is needed, and the slice
is what carries the hashes. The digest above exists so a phase-2 transcript can
record which reference string it built on without carrying twenty megabytes of
it.

The permutation test runs against the real basis too — elements 11,111 and
22,222 of the genuine 2^15 basis, swapped in both groups, refused.

## Phase 2: built, and what each part rests on

Phase 2 is circuit-specific, so it has to be ours.

`ark-groth16` 0.5 has no MPC module. That was checked in its source, not
assumed — a web search confidently said otherwise. The two mature
implementations are Filecoin's `phase2` (bellman) and gnark's `mpcsetup` (Go),
and both want the circuit expressed in their own constraint system. So the
options were:

| | cost | risk |
|---|---|---|
| implement it over arkworks | a real piece of protocol code | ours to get right, and a subtle error is invisible |
| Filecoin's `phase2` | re-express 18,107 constraints in bellman | **two circuits that must be identical**, with nothing checking that they are |
| gnark's `mpcsetup` | re-express them in gnark | the same, plus a Go/Rust boundary |

The second and third look cheaper than they are. A second implementation of
this circuit is not a translation exercise; it is a second chance to get the
relations wrong, and the ceremony would fix whichever one it was fed. The
circuit already exists once in arkworks and is cross-checked against the FunC,
so the first option keeps the number of circuits at one. That is what was
done, in `tools/shielded-pool-ceremony/src/{phase2,contribution,entropy,secret}.rs`.

### The starting key, which can be checked by equality

A circuit-specific setup is a linear map from the phase-1 string to a proving
key, and everything in that map except `gamma` and `delta` is fixed by the
circuit. So the ceremony begins at `gamma = delta = 1`: a key with **no secrets
in it at all**, a deterministic function of the slice and the R1CS, which two
people must be able to build byte-for-byte alike.

That makes this stage checkable in a way nothing later is, and it is checked
the strong way: `phase2_initial.rs` builds a key through our map and through
`ark_groth16::generate_parameters_with_qap` **on the same secrets**, and
compares element for element. On two small circuits, on a determinism check,
and on the real 18,107-constraint circuit.

One thing that stage settled is load-bearing elsewhere. The setup's evaluation
domain is `constraints + instance_variables`, not `max(constraints,
variables)`, because `instance_map_with_evaluation` gives each public input its
own Lagrange coefficient past the end of the constraints. Both round to 2^15
here so the slice was right either way — but the headroom was wrong, and the
headroom is the number somebody adding constraints reads.

### A contribution

Each participant draws a scalar `d`, replaces `delta` with `delta·d`, divides
the `L` and `H` queries by `d`, and destroys `d`. Everything else — `alpha`,
`beta`, `gamma`, the `A` and `B` queries, the input-consistency points — is
fixed by the circuit and must not move. Do this `n` times and the final `delta`
is a product no single participant knows: forging a proof needs all `n`, so the
parameters are sound if **one** participant was honest. That is why a ceremony
wants many participants rather than trustworthy ones.

Three checks make a contribution worth something, and none of them needs the
secret:

1. **A proof of knowledge.** The participant publishes `s` and `s·d` in G1 and
   `h·d` in G2, where `h` is hashed from the transcript together with `s` and
   `s·d`. Because `h` comes out of the transcript, the same proof is worthless
   at any other position, in any other ceremony, and after any earlier entry
   has been altered.
2. **The same `d` moved `delta`**, by pairing the new `delta` against `h` and
   the old against `h·d`.
3. **The same `d` divided the queries**, batched against weights the verifier
   draws *after* seeing the key — so a key built to pass a known weighting
   cannot be.

`gamma` stays at one throughout. That is the established shape of a phase 2,
not an economy: `gamma` separates the public-input terms from the rest and its
secrecy is not what soundness rests on, being non-zero is.

### The audit needs no intermediate keys

This is the property that makes a ceremony checkable years later.
`verify_chain` takes three things:

* the **starting key**, which anyone rebuilds from the committed phase-1 slice
  and the circuit;
* the **published contributions**, 672 bytes each whatever the circuit's size;
* the **finished key**, which is the artifact in use.

Nothing else has to have been kept, and nothing that was kept has to be
trusted. It works because the starting `delta` is one, so the final queries are
the starting ones divided by the whole product while the final `delta` *is*
that product — pairing one against the other cancels it without anyone knowing
it.

### The ending

`finalise` applies a last contribution whose scalar is a hash of a **public
random beacon**. It adds no secrecy — anybody can recompute the scalar — and a
ceremony consisting only of it is worth nothing.

**It also does not rescue a ceremony whose participants all colluded**, and an
earlier version of this page said it did. The final `delta` is
`d_1 · … · d_n · d_beacon`, and `d_beacon` is a hash of published bytes: a
coalition holding every `d_i` can compute it like anyone else, so it holds the
product. **Security rests entirely on at least one participant having
destroyed their scalar**, with or without a beacon.

What the beacon does add is that the finished parameters depend on a value
nobody could have predicted while contributing, so no participant could steer
`delta` towards something prepared in advance.

That property is procedural, and the code cannot check it. **The beacon has to
be named and fixed before the ceremony starts**; one chosen afterwards is
decoration. What the code does check is that the finalising step is exactly the
one those bytes determine — it is recomputed and compared byte for byte, not
merely verified as a valid contribution, because a participant-chosen scalar
wearing the beacon's name would verify perfectly well.

### What the evidence is

`test/shielded-pool/mutations-ceremony.py` weakens one check at a time and
requires the suite to report it **by name**. 45 mutations; 44 are killed by the
test aimed at them, and one is recorded as not test-backed.

The by-name rule is not pedantry. Several checks here shadow each other, and
the first version of this suite was green against a build with the chain link
removed, another with the proof-of-knowledge pairing removed, and another with
the cross-group check removed — the transcript binding or the query check was
catching each attack first. The tests that close those gaps build a
contribution by hand from chosen scalars, with one knob turned, so exactly one
comparison can fail.

The recorded survivor is `pok-challenge-points`: dropping the participant's own
`s` and `s·d` from the challenge hash. That input is what makes the knowledge
extractor work in the security proof this follows; no concrete forgery in the
suite distinguishes a build without it, and inventing a test that appeared to
would be worse than recording the gap.

### And the binaries, which no Rust test touches

The library's tests call `contribute` and `verify_chain` directly, on keys they
built in memory. Everything between a person and those functions — reading a
directory somebody else wrote, refusing to begin over an existing ceremony,
refusing to contribute after the beacon, noticing an artifact that was altered
on disk — is code none of them exercises, and building a binary is not running
it.

`test/shielded-pool/ceremony-cli.py` drives all four commands the way people
will, then breaks one artifact at a time and requires a refusal *for the right
reason*. Writing it found a real hole:

> **The first contribution had nothing tying `key.bin` to the starting key.**
> With no contributions yet there is no chain for `verify_chain` to audit, and
> `read_key` only establishes that the file matches the record's
> `key_sha256` — but whoever prepared the directory wrote both of those. A
> record could carry the true `starting_key_sha256` beside a `key_sha256` for
> some *other* valid proving key over the same circuit, and the first
> participant would contribute to that instead, to no effect on the key
> everyone else was working on.

Closed by requiring, when the chain is empty, that the record's current key be
the starting key this checkout rebuilt. The script now constructs exactly that
directory and requires the refusal.

### Two pairing libraries, asked the same questions

The audit an outsider runs is arkworks all the way down: the pairings, the
group law and the multiexponentiations are one library's, used one way, by one
author. The tests show it accepts honest chains and refuses the forgeries aimed
at it — and a pairing check that is *consistently* wrong would do both, while
meaning something other than what is written down.

So `crosscheck.rs` implements the same four checks against **blst**, the
library the chain itself verifies proofs with, and `crosscheck_agrees.rs` puts
every chain to both. The assertion is not "it was refused" but **"they
agreed"**: honest chains of one, two and three contributions, one ending in a
beacon, every forgery from the suite, each hand-built one-knob forgery, the
identity substituted into each of a contribution's five points, and a sweep of
72 perturbations that scale one field at a time. No disagreement.

Independent: the pairing, the final exponentiation, the group law, the scalar
multiplication — where a missing negation or a reversed argument hides, and
where "it passes its own tests" is not evidence. The blst side compares two
Miller loops with `blst_fp12_finalverify` where the arkworks side negates an
input and asks whether the product is one, and it accumulates the batched sums
one point at a time rather than through Pippenger.

**Not** independent: the author, the repository, the point encoding (shared on
purpose — it is normative) and the *meaning* of the checks. An error in what
ought to be checked is reproduced faithfully on both sides. This narrows the
gap that "a second verifier" names; it does not close it.

#### What it found immediately

Adding the second implementation to the battery was itself a test of the
battery, and it failed it twice.

First, **every one of the seven blst mutations survived** — because the battery
was not running the agreement suite at all. The line that should have added it
was written against the wrong file and `str.replace` did nothing, silently. A
second implementation that nothing exercises is worse than none, because it
reads like evidence.

Then, with the suite running, six died and one lived: **dropping the scalar
multiplication from the batched sum changed no verdict anywhere.** That is
correct, and it says something about the suite rather than about blst. An
*unweighted* sum accepts honest chains and catches every forgery that scales a
single query point — which was all of them. The weights exist for a
compensating pair: add a point to one query entry and subtract it from
another, and the plain sum is unchanged while the weighted one differs by
`(rho_i - rho_j) * v`. Nothing had ever built one, so nothing had ever shown
the weights doing anything, **on either side**.

`the_weights_are_what_catches_a_compensating_pair` builds one — asserting first
that the plain sums really are equal, so the test is about weights and not
about something else — and it kills three mutations: the blst scalar being
dropped, the arkworks weights coming from a constant seed, and the arkworks
weights being all one.

It also corrected a name. The blst case was filed expecting
`both_accept_an_honest_chain` to go red, and the battery refused it as
`WRONG-TEST`: an honest chain does not care how it is weighted.

And one more, which is the same failure as the first in a different costume.
With two test targets, eight *arkworks*-side mutations came back `WRONG-TEST`,
reporting that they had been caught by the agreement suite rather than by the
test named for them. They had been caught by both — but **`cargo test` stops at
the first failing target**, so the second suite never ran and its failures were
not in the output to be found. `--no-fail-fast` is load-bearing here, and
without it the battery was reporting the instrument stopping as though it were
a result.

### Breaking something the wrong way proves nothing

This came up four separate times while writing the above, in four different
places, and it is the single easiest mistake to make here. A test that breaks
an artifact has to break it in a way that **only the check under test** can
notice, and the natural way to break something is almost never that way:

| broken how | refused by | what it proved about the intended check |
|---|---|---|
| a bit flipped in `contributions.bin` | blst, `BLST_POINT_NOT_ON_CURVE` | nothing — the point decoder |
| `beacon.bin` swapped | the record's own `beacon_sha256` | nothing — the record's self-consistency |
| a bit flipped in `key.bin` | `deserialize_compressed`, in a second | nothing — a corrupted curve point |
| `b"not a key"` written as `key.bin` | the same | nothing — and this one hid behind an `||` in the assertion |

The fixed versions are: **exchange** two contributions, so every point stays
valid and only the chain can object; swap `beacon.bin` **and** rewrite
`beacon_sha256` to match, so only the recomputation is left; and change the
*record's* `key_sha256` rather than the key, so the key still reads and only
the comparison between the two files can fail.

Three of the four were found by the mutation battery reporting a survivor. The
fourth was found by the battery too — `record-key-digest` stayed green — and
its test had been written permissively enough (`contains(A) || contains(B)`) to
pass either way, which is the shape of an assertion that has stopped asserting.

Two of the script's own checks had to be sharpened for the same reason the
mutation battery names its tests.

### The whole chain, once, on the real thing

Every section above is evidence about one link, and a chain of verified links
can still be bolted together wrongly. So
`crosscheck/tests/ceremony_end_to_end.rs` runs the whole thing and asks the
only question that settles it:

> the committed phase-1 slice -> Lagrange basis -> starting key -> two
> contributions -> a beacon -> 1,248 bytes -> **a deployed pool that accepts a
> real private transfer**

Nothing in it is mocked or shortened. Measured on the real circuit:

```
slice: the zcash ceremony, 18874464 bytes
starting key: 19 IC points, L 18215, H 32767
3 contributions, 2016 bytes of published record
ceremony key 8b3bd9e9d72af025 -> pool 0:58a21c71… -> transact exit 0 at 1144235 gas
a proof under the pre-ceremony key: exit 262
```

The last line is the sharp one. Everything above it would also pass for a
pipeline that quietly handed back the key it started from — and that key's
`delta` is one, known to everyone, forgeable by anyone. A pool carrying the
ceremony's key has to *refuse* a proof made under the pre-ceremony key, and it
does.

The key that test produces comes from labelled test seeds, so it is a
development key and no more deployable than the one in `groth16.rs`. What it
establishes is that the machinery produces a key the chain accepts.

### What none of it establishes

**That a participant's scalar was drawn unpredictably, and destroyed.** A
contribution from a scalar the participant published verifies exactly as well
as one from a scalar they burned. There is no check anywhere for this and there
cannot be.

What there is instead is arranged so the careless version does not compile:

* the library offers **one** entropy source, the operating system, and has no
  seeded constructor anywhere in it — a repeatable source for tests lives in
  the test crate, where nothing that ships can reach it;
* participant-supplied material can only be **stirred in**, never substituted,
  so a draw is unpredictable if *either* the system generator or the material
  was;
* the scalar is reduced from **64 bytes, not 32**: the group order is a shade
  under 2^255, so a 256-bit string biases the result by a fraction near 2^-128;
* a source returning one repeated byte is refused — the shape of a stub, a mock
  or a device that opened and returned nothing;
* the scalar lives in a type that is not `Clone`, not `Serialize`, has no
  `Display`, prints `Secret(<withheld>)` from `Debug`, never appears in a
  return type, and wipes itself on drop. The value derived from it that would
  equally give it away — its inverse — is wiped before the function returns.

None of that defends against an attacker reading process memory, and it is not
meant to. It defends against the way these secrets are actually lost, which is
a developer adding a print statement to see what is going on.

### Cost

Measured on the real circuit — 18,107 constraints, an `L` query of 18,215
points and an `H` query of 32,767:

| | release | debug |
|---|---|---|
| one contribution | **10.0 s** | 120 s |
| auditing the chain | **0.2 s** | 2.4 s |

So a participant waits about ten seconds, not two minutes — the debug column is
there because that is what an unsuspecting `cargo test` reports, and a ceremony
scheduled around it would ask twelve times too much of everyone's time. The
test prints which build it measured for that reason.

A participant's wait is dominated by two multiexponentiations over the `L` and
`H` queries. An auditor's work grows only in the per-contribution pairings; the
query check is a single batched pair however many people took part.

## The acceptance gate

Whatever produces the key, this is what says it is usable.
`shielded_pool_circuit_crosscheck::acceptance` **deploys a pool carrying
exactly the candidate bytes, proves a real transfer under the matching proving
key, sends it, and requires the contract to accept.** Everything short of that
is a claim about a serializer.

It reports the key's digest, its IC count, its length, the deployment address
the key implies, and the transact's exit code.

Every key in `ceremony_acceptance.rs` is built from a seed in that file, so
until the `ceremony-gate` example existed there was no way to point the gate at
an actual ceremony's output -- the tests never read a ceremony directory. That
example is the missing step; `parameters_with_verifying_key` and the genesis
binary's `--verifying-key` are the one after it. See **And then the 1,248 bytes
become a deployment** above.

Five tests establish that the gate judges rather than nods:

* it accepts the key this repository ships (digest `5b760517…`);
* it accepts **a key it has never seen**, from a different setup — which is the
  case a ceremony actually presents, and the one a fixture-shaped check would
  fail;
* it **refuses a proof made under a different key** from the one deployed
  (exit 262). Without this the two above would pass for a gate that never
  compares the proof to the key at all;
* it refuses a key of the wrong length;
* and two different keys give two different deployment addresses — which is
  why no address can be published before the ceremony ends.

## Running a ceremony

> The commands are below. **What turns running them into a ceremony is in
> `doc/shielded-pool-phase2-runbook.md`** -- what has to be published before
> the first contribution, who counts as an independent participant, and who
> checks afterwards. None of it is in the code and none of it can be.

Four commands. Each one rebuilds the starting key from the committed slice
before doing anything, which is the slow part (a couple of minutes) and the
reason to trust the result: a participant who reads a starting key out of the
directory has checked that their contribution was applied to *something*.

```
# the coordinator opens it
cargo run --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml \
    --bin phase2-begin -- /path/to/ceremony

# each participant, on their own machine
cargo run --release ... --bin phase2-contribute -- /path/to/ceremony
#   --entropy-file <path>   stirs extra material into the draw: dice, a
#                           hardware token, a second machine. Mixed in, never
#                           substituted, so the result is unpredictable if
#                           *either* source was.

# the coordinator closes it, with the beacon named before it opened
cargo run --release ... --bin phase2-finalise -- /path/to/ceremony beacon.bin

# anybody, afterwards
cargo run --release ... --bin phase2-verify -- /path/to/ceremony --vk-out vk.bin
```

`phase2-contribute` audits the chain it was handed **before** drawing anything.
A contribution added to a chain that does not audit is wasted: the ceremony
gets re-run and the participant's scalar — destroyed by then — cannot be used
again.

### And then the 1,248 bytes become a deployment

`phase2-verify --vk-out` writes the key; two steps turn it into something to
deploy, and both have to pass before anyone does.

```
# does the chain accept it? deploys a pool carrying exactly these bytes,
# proves a real transfer under the ceremony's proving key, and requires exit 0
TOS_ROOT=<a checkout with a built func/fift> \
cargo run --release --manifest-path \
    tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --example ceremony-gate -- /path/to/ceremony

# what would it deploy as? the key is part of the genesis state, so it fixes
# the state hash, so it fixes the address
cargo run --manifest-path tools/shielded-pool-genesis/Cargo.toml --bin genesis -- \
    . out/manifest.json --verifying-key vk.bin
```

Until `--verifying-key` existed there was no supported route from a ceremony's
output to a genesis state: the only way was hand-editing the development
fixture, which is exactly the sort of step that gets done once, wrongly, under
time pressure. Everything except the key still comes from
`development_parameters`, so there is no second copy of the profile, the
Poseidon2 manifest or the constants to drift.

It is also how a *candidate* key's deployment address is found before anyone
commits to it — and the reason no address can be published before a ceremony
ends is that one bit of the key moves it.

### What a ceremony directory holds

```
key.bin            the proving key as it now stands  (~10 MB)
contributions.bin  every published contribution, 672 bytes each, in order
beacon.bin         the beacon output it was closed with
ceremony.json      what each step was, and the digests to compare
```

No intermediate key is kept. That is not a space saving, it is the shape of the
audit: `verify_chain` needs the starting key, the record and the finished key,
so keeping intermediates would create a second source of truth nobody checks.
The beacon step is recomputed from `beacon.bin` and the *previous step's
published `delta`*, so it too needs no key.

There is no field anywhere for a participant's scalar, no optional file and no
debug mode that writes one. **A ceremony directory can be published whole the
moment it exists**, and that is the intended use.

### What a participant publishes

Two digests, signed, saying they drew a scalar and destroyed it:

```
contribution   <sha256 of their 672 bytes>
transcript     <the transcript after their step>
```

The second names their position in a way nobody can move afterwards: the
challenge every later contribution is bound to is hashed from it, so reordering
the chain, dropping an entry or substituting one invalidates every proof after
the change.

Attribution is deliberately *not* in `ceremony.json`. A name in the record
would look as though something had checked it.

## What is needed from people

1. **Participants.** Any number; the property needed is that at least one
   destroys their randomness. Each contributes to the phase-2 transcript and
   publishes an attestation.
2. **A random beacon** to finalise, fixed in advance: what it is, at what
   height or time, and who witnesses it. The mechanism is built and
   `phase2-verify` recomputes the finalising step from the beacon's bytes, so
   a scalar wearing the beacon's name is caught. What no program can check is
   *when* the beacon was chosen — and a beacon chosen after the contributions
   are in is decoration. That decision is the thing still outstanding.
3. **A second verifier.** Someone outside this repository running the
   acceptance gate against the produced key and getting the same digest. The
   audit is now cross-checked against a second pairing library (see **Two
   pairing libraries, asked the same questions**), which removes the
   library-convention half of this. The half that remains — a second reading of
   *what ought to be checked* — needs a person who did not write it.

## What must be decided before it starts

A ceremony fixes the circuit, so anything that changes the circuit has to be
settled first — it becomes unfixable the moment the verifying key is frozen.
This section listed two such questions. **One of them is not open.**

### 1-in/2-out — decided, declined

Offered to the owner on 2026-09-21 as one of three levers for the gas price,
and **declined with the other two**; the tenfold basechain price cut was taken
instead. That is a decision to keep 2-in/3-out, and this document went on
listing it as outstanding — which would have held up a ceremony for a question
already answered. The record is
`memo/privacy/measurements/gas-price-cut-20260921/`.

Reopening it is possible and would be a new decision, so the numbers are worth
stating plainly, including how they were arrived at:

* the **−333,000 gas** is a **sum of separately measured components**, not a
  measurement of a 1-in/2-out transact — one nullifier insertion (~204,000, the
  refusal ladder's second row), one ML-DSA-44 authorization (~65,500, the
  difference between its last two rows once the 204,493 proof is taken out) and
  one commitment append. No 1-in/2-out circuit has ever been built, so nothing
  has measured the whole;
* it is **not a small change**. Section 10's public input vector is frozen at
  eighteen elements and names two nullifiers, three note bodies, three output
  data hashes and two authorization key hashes. One input and one output fewer
  is fourteen, so the verifying key becomes 1,056 bytes rather than 1,248, and
  the FunC verifier, the wire format, the wallet and the genesis state all move
  with it;
* the saving would also be slightly larger than 333,000, because `vk_x` is a
  multiexponentiation over the public inputs and there would be four fewer.
  Nobody has measured that either.

### Charging the recovery's compute to the recovered amount — open

This one is genuinely open, and it is the more consequential of the two.

Section 14.2 makes `withdrawal_fee` cover the payout's forward fee **plus a
whole bounded recovery**. The fee is written into the genesis config store and
is immutable, while the check that enforces it reads the chain's **live**
prices — so if governance ever raises the gas price past what the fee affords,
every withdrawal fails at exit 243 permanently, while deposits and transfers
carry on. Money goes in and cannot come out, with no recovery, because the fee
cannot be changed. That is why 50,000,000 was re-derived and **kept** rather
than lowered: it is sized against the highest price the chain could reach, and
it survives about 3.4× the live price
(`memo/privacy/measurements/withdrawal-fee-derivation-20260921/`).

Charging the recovery's compute to the recovered amount — the money is back in
the pool by the time the note is minted — removes the recovery term from that
floor entirely. What remains is the forward fee, which prices bytes rather than
work and was held fixed through the price cut. The cliff does not disappear,
but the fee sized against it gets much smaller and the margin much larger.

**Decided and done, 2026-09-22.** Section 15.4 now charges
`get_compute_fee(0, BOUNCE_GAS_CEILING)` -- 1,466,669 nanotos at today's price
-- to the bounce, and section 14.2's floor is the forward fee alone: 885,601,
with no gas term in it. The same 50,000,000 fee is 56.5x that floor and the
ratio no longer decays when gas is repriced.

It turned out **not to touch the circuit**. The recovery note's amount is
fixed by the contract at bounce time and `recovery_template_hash` commits to
the owner and the payload, never to a value, so nothing the prover signs
changes. This page said otherwise and was wrong.

So **nothing circuit-shaped is outstanding, and a ceremony is not waiting on a
decision.** The genesis state hash moved with the profile
(`fd9303eb...` to `ced6d862...`), which is free while no address is published.

`config.withdrawal_fee` was re-derived with it, 50,000,000 to **20,000,000**:
the same safety standard the previous derivation settled on, applied to the
only term the floor still has. It clears the forwarding price this chain
charged until `3c7f4036d` by 3.76x, where 50,000,000 cleared the gas price it
had just left by 3.35x. The genesis state hash moved again.

It has moved since, most recently on 2026-09-23 when section 14.1's gas
ceilings stopped being sampled maxima and became derived bounds: the profile's
bytes are the `profile_hash`, the hash is in the config store, the store is in
the state, and the state is half the address. That is the intended coupling and
not a surprise. **The current value is in
`doc/shielded-pool/genesis-manifest.json`**, which the generator writes; a hash
quoted in prose is a copy, and a copy of a hash is exactly the thing that goes
stale without anything failing. This page named one for two generations after
it stopped being true.

**Nothing is outstanding on this page that a ceremony has to wait for.**

## Running the checks

Not the ceremony -- that is above. These are the tests, and the slices are in
the repository so nothing has to be fetched first.

```
# everything, including the real slices, their hashes and the basis change
cargo test --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml

# what a slice actually is, the basis change, and the reference string phase 2
# would start from -- one run, because a verified slice on its own is not yet
# usable and the step between is easy to forget
cargo run --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml \
    --bin verify-phase1-slice -- \
    artifacts/phase1/phase1-zcash-2m15.bin artifacts/phase1/phase1-zcash-2m15.json

# phase 2 on the real circuit -- one contribution and one audit over 18,107
# constraints, with the timings a ceremony has to be planned against
cargo test --release --manifest-path tools/shielded-pool-ceremony/Cargo.toml \
    --test phase2_contribution -- --ignored --nocapture

# the evidence that the phase-2 checks are checks: each one removed in turn,
# and the test aimed at it required to go red by name
uv run python test/shielded-pool/mutations-ceremony.py

# the binaries, driven the way people will drive them, then broken one
# artifact at a time. Building a binary is not running it, and no Rust test
# here touches them: they call the library directly with keys built in memory
uv run python test/shielded-pool/ceremony-cli.py

# the whole pipeline: the committed slice through a real ceremony to a pool
# that accepts a private transfer. Minutes, and the one that would catch a
# mistake between two links rather than inside one
TOS_ROOT=<a checkout with a built func/fift> \
cargo test --release --manifest-path \
    tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --test ceremony_end_to_end -- --ignored --nocapture

# the gate a ceremony's verifying key has to pass
cargo test --release --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --test ceremony_acceptance

# and, to confirm a stored slice is still what the transcript serves:
# re-fetch and require the hashes to be identical
uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1
# --transcript filecoin for the other ceremony
```

Fetching and judging are separate on purpose: one half needs the network and no
cryptography, the other needs cryptography and no network. That separation is
why a re-fetch is a check rather than a refresh — the hashes it has to
reproduce are already in git.
