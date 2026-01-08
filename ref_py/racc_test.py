"""
racc_core.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Masked Raccoon signature scheme: Core implementation.
"""
import copy
import os
import time

from Crypto.Hash import SHAKE256
from nist_kat_drbg import NIST_KAT_DRBG
from mask_random import MaskRandom
from polyr import *

BYTEORDER = "little"


class ConsistencyError(Exception):
    """Raised when redundant copies diverge in fault‑attack safe operations."""


class Raccoon:
    """Core implementation of the Masked Raccoon signature scheme."""

    ### Public Interface

    #   initialize
    def __init__(self,  bitsec,
                        q, nut, nuw, rep, ut, uw, n, k, ell, w, d,
                        masking_poly=MaskRandom().random_poly,
                        random_bytes=os.urandom, kappa=512):
        """Initialize a Raccoon instance.

        Args:
            bitsec: security parameter in bits.
            q: modulus used for polynomial arithmetic.
            nut, nuw: bit shifts for rounding operations.
            rep: number of repetitions for noise addition.
            ut, uw: noise bit lengths for different vectors.
            n: polynomial degree.
            k, ell: matrix dimensions.
            w: weight of the challenge polynomial.
            d: number of masking shares.
            masking_poly: callable returning random masking polynomials.
            random_bytes: function returning random bytes (for seeds).
            kappa: length of the seed for key generation.
        """

        self.name   =   f'Raccoon-{bitsec}-{d}'
        self.bitsec =   bitsec
        self.d      =   d
        self.q      =   q
        self.q_bits =   q.bit_length()
        self.n      =   n
        self.k      =   k
        self.ell    =   ell
        self.nut    =   nut
        self.nuw    =   nuw
        self.rep    =   rep
        self.ut     =   ut
        self.uw     =   uw
        self.w      =   w

        # Derived sizes for hashing and serialization
        self.sec    =   self.bitsec//8  # pre‑image resistance, bytes
        self.crh    =   2*self.sec      # collision resistance, bytes
        self.as_sz  =   self.sec        # A seed size
        self.mu_sz  =   self.crh        # mu digest H(tr, m) size
        self.tr_sz  =   self.crh        # tr digest H(pk) size
        self.ch_sz  =   self.crh        # Challenge hash size
        self.mk_sz  =   self.sec        # serialization "key" size

        self.masking_poly = masking_poly
        self.random_bytes = random_bytes

        #   calculate derived parameters
        self._compute_metrics()

    def keygen(self):
        """Raccoon keypair generation (basic variant)."""

        #   --- 1.  seed <- {0,1}^kappa
        seed = self.random_bytes(self.as_sz)

        #   --- 2.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   --- 3.  [[s]] <- ell * ZeroEncoding(d)
        ms = [ self._zero_encoding() for _ in range(self.ell) ]

        #   --- 4.  [[s]] <- AddRepNoise([[s]], ut, rep)
        ms = self._vec_add_rep_noise( ms, self.ut, self.rep )

        #   --- 5.  [[t]] := A * [[s]]
        ms_ntt = mat_ntt(ms)
        mt = mat_intt(mul_mat_mvec_ntt(A_ntt, ms_ntt))

        #   --- 6.  [[t]] <- AddRepNoise([[t]], ut, rep)
        mt = self._vec_add_rep_noise( mt, self.ut, self.rep )

        #   --- 7.  t := Decode([[t]])
        t = [ self._decode(mti) for mti in mt ]

        #   --- 8.  t := round( t_m )_q->q_t
        qt  = self.q >> self.nut
        t = [ poly_rshift(ti, self.nut, qt) for ti in t ]

        #   --- 9.  return ( (vk := seed, t), sk:= (vk, [[s]]) )
        vk = (seed, t)
        msk = (seed, t, ms_ntt)
        return msk, vk

    def keygen_fault_attack_safe(self, e: int):
        """Raccoon keypair generation with redundancy for fault attack resistance."""

        #   --- 1.  seed <- {0,1}^kappa
        seed = self.random_bytes(self.as_sz)
        lst_seed = [copy.deepcopy(seed) for _ in range(e)]

        #   --- 2.  A := ExpandA(seed)
        lst_A_ntt = [mat_ntt(self._expand_a(seed)) for seed in lst_seed]

        #   --- 3.  [[s]] <- ell * ZeroEncoding(d)
        # Create e independent copies of zero encodings for each share
        lst_ms = [self._lst_zero_encoding(e) for _ in range(self.ell)]
        # Transpose to shape [e][ell]
        lst_ms = [[lst_ms[j][i] for j in range(self.ell)] for i in range(e)]

        #   --- 4.  [[s]] <- AddRepNoise([[s]], ut, rep)
        lst_ms = self._lst_vec_add_rep_noise( lst_ms, self.ut, self.rep )

        #   --- 5.  [[t]] := A * [[s]]
        lst_ms_ntt = [mat_ntt(ms) for ms in lst_ms]
        lst_mt = [mat_intt(mul_mat_mvec_ntt(A_ntt, ms_ntt)) for A_ntt, ms_ntt in zip(lst_A_ntt, lst_ms_ntt)]

        #   --- 6.  [[t]] <- AddRepNoise([[t]], ut, rep)
        lst_mt = self._lst_vec_add_rep_noise( lst_mt, self.ut, self.rep )

        #   --- 7.  t := Decode([[t]])
        lst_t = [[ self._decode(mti) for mti in mt ] for mt in lst_mt ]

        #   --- 8.  t := round( t_m )_q->q_t
        lst_qt  = [self.q >> self.nut for _ in range(e)]
        lst_t = [[ poly_rshift(ti, self.nut, qt) for ti in t ] for t, qt in zip(lst_t, lst_qt)]

        #   --- 9.  return ( (vk := seed, t), sk:= (vk, [[s]]) )
        vk = (lst_seed, lst_t)
        msk = (lst_seed, lst_t, lst_ms_ntt)
        return msk, vk

    def sign_mu(self, msk, mu):
        """Signing procedure of Raccoon (core: signs the mu hash)."""

        #   --- 1.  (vk, [[s]]) := [[sk]], (seed, t) := vk      [ caller ]
        (seed, t, ms_ntt) = msk

        #   --- 2.  mu := H( H(vk) || msg )                     [ caller ]

        #   --- 3.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   (restart position.)
        rsp_norms = False
        while not rsp_norms:

            #   --- 4.  [[r]] <- ell x ZeroEncoding()
            mr = [ self._zero_encoding() for _ in range(self.ell) ]

            #   --- 5.  [[r]] <- AddRepNoise([[r]], uw, rep)
            mr = self._vec_add_rep_noise( mr, self.uw, self.rep )
            mr_ntt = mat_ntt(mr)

            #   --- 6.  [[w]] := A * [[r]]
            mw = mat_intt(mul_mat_mvec_ntt(A_ntt, mr_ntt))

            #   --- 7.  [[w]] <- AddRepNoise([[w]], uw, rep)
            mw = self._vec_add_rep_noise( mw, self.uw, self.rep )

            #   --- 8.  w := Decode([[w]])
            w = [ self._decode(mwi) for mwi in mw ]

            #   --- 9.  w := round( w )_q->q_w
            qw  = self.q >> self.nuw
            w = [ poly_rshift(wi, self.nuw, qw) for wi in w ]

            #   --- 10. c_hash := ChalHash(w, mu)
            c_hash  = self._chal_hash(mu, w)

            #   --- 11. c_poly := ChalPoly(c_hash)
            c_ntt   = ntt(self._chal_poly(c_hash))

            #   --- 12. [[s]] <- Refresh([[s]])
            for si in ms_ntt:
                self._refresh(si)

            #   --- 13. [[r]] <- Refresh([[r]])
            for ri in mr_ntt:
                self._refresh(ri)

            #   --- 14. [[z]] := c_poly * [[s]] + [[r]]
            mz_ntt = [[[ None ] for _ in range(self.d)]
                                    for _ in range(self.ell)]
            for i in range(self.ell):
                for j in range(self.d):
                    mz_ntt[i][j] = poly_add(mul_ntt(c_ntt, ms_ntt[i][j]),
                                            mr_ntt[i][j])

            #   --- 15. [[z]] <- Refresh([[z]])
            for zi in mz_ntt:
                self._refresh(zi)

            #   --- 16. z := Decode([[z]])
            z_ntt = [ self._decode(mzi) for mzi in mz_ntt ]

            #   --- 17. y := A*z - 2^{nu_t} * c_poly * t
            y = mul_mat_vec_ntt(A_ntt, z_ntt)
            for i in range(self.k):
                tp = poly_lshift(t[i], self.nut)
                ntt(tp)
                y[i] = poly_sub( y[i], mul_ntt(c_ntt, tp) )
                intt(y[i])

            #   --- 18. h := w - round( y )_q->q_w
            for i in range(self.k):
                y[i] = poly_rshift(y[i], self.nuw, qw)
                y[i] = poly_sub(w[i], y[i], qw)
                y[i] = poly_center(y[i], qw)
            h = y   #   (rename)

            #   --- 19. sig := (c_hash, h, z)                   [caller]

            #   --- 20. if CheckBounds(sig) = FAIL goto Line 4
            z = [intt(zi.copy()) for zi in z_ntt]
            rsp_norms = self._check_bounds(h, z)

        #   --- 21. return sig
        sig = (c_hash, h, z)
        return sig

    def sign_mu_fault_attack_safe(self, lst_msk: tuple, lst_mu: list, e: int, inject_error: callable = None) -> tuple:
        """Signing procedure of Raccoon with fault‑attack safety.

        Args:
            lst_msk: tuple containing redundant copies of secret key (seed list, t list, s list in NTT form).
            lst_mu: list of redundant copies of message digests.
            e: number of redundant copies.
            inject_error: optional callback to introduce faults for testing.

        Returns:
            A tuple (lst_c_hash, lst_h, lst_z) where each element is a list of length e containing the redundant outputs.
        """

        if not inject_error:
            inject_error = lambda _: None

        #   --- 1.  (vk, [[s]]) := [[sk]], (seed, t) := vk      [ caller ]
        (lst_seed, lst_t, lst_ms_ntt) = lst_msk
        inject_error(lst_seed)
        inject_error(lst_t)
        inject_error(lst_ms_ntt)

        #   --- 2.  mu := H( H(vk) || msg )                     [ caller ]

        #   --- 3.  A := ExpandA(seed)
        lst_A_ntt = [mat_ntt(self._expand_a(seed)) for seed in lst_seed]
        inject_error(lst_A_ntt)

        #   (restart position.)
        lst_rsp_norms = []
        while not lst_rsp_norms or not all(lst_rsp_norms):
            #   --- 4.  [[r]] <- ell x ZeroEncoding()
            lst_mr = [ self._lst_zero_encoding(e) for _ in range(self.ell) ]
            lst_mr = [[lst_mr[j][i] for j in range(self.ell)] for i in range(e)]
            inject_error(lst_mr)

            #   --- 5.  [[r]] <- AddRepNoise([[r]], uw, rep)
            lst_mr = self._lst_vec_add_rep_noise( lst_mr, self.uw, self.rep )
            inject_error(lst_mr)
            lst_mr_ntt = [mat_ntt(mr) for mr in lst_mr]
            inject_error(lst_mr_ntt)

            #   --- 6.  [[w]] := A * [[r]]
            lst_mw = [mat_intt(mul_mat_mvec_ntt(A_ntt, mr_ntt)) for A_ntt, mr_ntt in zip(lst_A_ntt, lst_mr_ntt)]
            inject_error(lst_mw)

            #   --- 7.  [[w]] <- AddRepNoise([[w]], uw, rep)
            lst_mw = self._lst_vec_add_rep_noise( lst_mw, self.uw, self.rep )
            inject_error(lst_mw)

            #   --- 8.  w := Decode([[w]])
            lst_w = [[ self._decode(mwi) for mwi in mw ] for mw in lst_mw]
            inject_error(lst_w)

            #   --- 9.  w := round( w )_q->q_w
            lst_qw  = [self.q >> self.nuw for _ in range(e)]
            inject_error(lst_qw)
            lst_w = [[ poly_rshift(wi, self.nuw, qw) for wi in w ] for w, qw in zip(lst_w, lst_qw)]
            inject_error(lst_w)

            #   --- 10. c_hash := ChalHash(w, mu)
            # Compute challenge hash separately for each copy
            lst_c_hash  = [self._chal_hash(mu, w) for mu, w in zip(lst_mu, lst_w)]
            inject_error(lst_c_hash)

            #   --- 11. c_poly := ChalPoly(c_hash)
            lst_c_ntt   = [ntt(self._chal_poly(c_hash)) for c_hash in lst_c_hash]
            inject_error(lst_c_ntt)

            #   --- 12. [[s]] <- Refresh([[s]])
            # Refresh each share of ms_ntt for each copy index
            # Refresh each share of the secret vector across all redundant copies.
            # Use self.ell rather than inspecting the first element to avoid
            # accidental mismatches if the structure is tampered with.
            for si in range(self.ell):
                self._lst_refresh(lst_ms_ntt, si)
            inject_error(lst_ms_ntt)

            #   --- 13. [[r]] <- Refresh([[r]])
            # Refresh each share of the randomness vector across all copies.
            for ri in range(self.ell):
                self._lst_refresh(lst_mr_ntt, ri)
            inject_error(lst_mr_ntt)

            #   --- 14. [[z]] := c_poly * [[s]] + [[r]]
            lst_mz_ntt = [[[[ None ] for _ in range(self.d)] for _ in range(self.ell)] for _ in range(e)]
            for idx in range(e):
                for i in range(self.ell):
                    for j in range(self.d):
                        # Multiply challenge polynomial with each share and add r
                        lst_mz_ntt[idx][i][j] = poly_add(mul_ntt(lst_c_ntt[idx], lst_ms_ntt[idx][i][j]), lst_mr_ntt[idx][i][j])
            inject_error(lst_mz_ntt)

            #   --- 15. [[z]] <- Refresh([[z]])
            # Refresh each share of the computed z vector across all copies.
            for zi in range(self.ell):
                self._lst_refresh(lst_mz_ntt, zi)
            inject_error(lst_mz_ntt)

            #   --- 16. z := Decode([[z]])
            lst_z_ntt = [[ self._decode(mzi) for mzi in mz_ntt ] for mz_ntt in lst_mz_ntt]

            #   --- 17. y := A*z - 2^{nu_t} * c_poly * t
            lst_y = [mul_mat_vec_ntt(A_ntt, z_ntt) for A_ntt, z_ntt in zip(lst_A_ntt, lst_z_ntt)]
            for idx in range(e):
                for i in range(self.k):
                    tp = poly_lshift(lst_t[idx][i], self.nut)
                    ntt(tp)
                    # Subtract c * tp in NTT domain and return to normal domain
                    lst_y[idx][i] = poly_sub( lst_y[idx][i], mul_ntt(lst_c_ntt[idx], tp) )
                    intt(lst_y[idx][i])
            inject_error(lst_y)

            #   --- 18. h := w - round( y )_q->q_w
            lst_h: list = []
            for idx in range(e):
                for i in range(self.k):
                    lst_y[idx][i] = poly_rshift(lst_y[idx][i], self.nuw, lst_qw[idx])
                    lst_y[idx][i] = poly_sub(lst_w[idx][i], lst_y[idx][i], lst_qw[idx])
                    lst_y[idx][i] = poly_center(lst_y[idx][i], lst_qw[idx])
                h = lst_y[idx]   #   (rename)
                lst_h.append(h)
            inject_error(lst_h)

            #   --- 19. sig := (c_hash, h, z)                   [caller]

            #   --- 20. if CheckBounds(sig) = FAIL goto Line 4
            # Convert shares back to time domain for z
            lst_z = [[intt(zi.copy()) for zi in z_ntt] for z_ntt in lst_z_ntt]
            inject_error(lst_z)
            lst_rsp_norms = [self._check_bounds(h, z) for h, z in zip(lst_h, lst_z)]
            inject_error(lst_rsp_norms)

        #   --- 21. Consistency check
        # Ensure all redundant copies agree; otherwise raise ConsistencyError.
        # The second argument provides a descriptive label used in the
        # exception message if a mismatch is detected.  It should
        # reflect the variable being checked for clarity.
        self._consistency_check(lst_c_hash, "lst_c_hash")
        self._consistency_check(lst_h, "lst_h")
        self._consistency_check(lst_z, "lst_z")

        #   --- 22. return sig
        return lst_c_hash, lst_h, lst_z

    @staticmethod
    def _consistency_check(lst: list, name: str) -> bool:
        """Ensure all elements in lst are identical. Raise on mismatch."""
        if not all(x == lst[0] for x in lst):
            raise ConsistencyError(f"Abort due to missing consistency in: {name}")
        return True


    def verify_mu(self, vk, mu, sig):
        """Verification procedure of Raccoon (core: verifies mu)."""

        #   --- 1.  (c hash, h, z) := sig, (seed, t) := vk
        (c_hash, h, z) = sig
        (seed, t) = vk

        #   --- 2.  if CheckBounds(h, z) = FAIL return FAIL
        if self._check_bounds(h, z) == False:
            return False

        #   --- 3.  mu := H( H(vk) || msg )                     [caller]

        #   --- 4.  A := ExpandA(seed)
        A_ntt = mat_ntt(self._expand_a(seed))

        #   --- 5.  c_poly := ChalPoly(c_hash)
        c_poly = self._chal_poly(c_hash)
        c_ntt = ntt(c_poly.copy())

        #   --- 6.  y = A * z - 2^{nu_t} * c_poly * t
        z_ntt = [ ntt(zi.copy()) for zi in z ]
        y = mul_mat_vec_ntt(A_ntt, z_ntt)
        for i in range(self.k):
            tp = poly_lshift(t[i], self.nut)    # p_t * t
            ntt(tp)
            y[i] = poly_sub( y[i], mul_ntt(c_ntt, tp) ) # y -= p_t * c * t
            intt(y[i])

        #   --- 7.  w' = round( y )_q->q_w + h
        qw  = self.q >> self.nuw
        for i in range(self.k):
            y[i] = poly_rshift(y[i], self.nuw, qw)
            y[i] = poly_add(y[i], h[i], qw)
        w = y;  #   (rename)

        #   --- 8. c_hash' := ChalHash(w', mu)
        c_hash_new = self._chal_hash(mu, w)

        #   --- 9. if c_hash != c_hash' return FAIL
        #   --- 10. (else) return OK
        rsp_hash = (c_hash == c_hash_new)

        return rsp_hash

    def set_random(self, random_bytes):
        """Set the key material RBG."""
        self.random_bytes   =   random_bytes

    def set_masking(self, masking_poly):
        """Set masking generator."""
        self.masking_poly = masking_poly

    #   --- internal methods ---

    def _compute_metrics(self):
        """Derive rejection bounds from parameters."""
        w   = self.w
        nuw = self.nuw
        nut = self.nut
        k   = self.k
        ell = self.ell
        n   = self.n
        d   = self.d

        sigma = (self.d * self.rep / 12)**0.5
        beta2 = n * ( (k + ell) *
            (((2**self.uw * sigma)**2) + w * ((2**self.ut * sigma)**2))
                + k * ( ((2**nuw)**2 / 6) +  w * ((2**nut)**2) / 12 ) )

        self.B22 = int(1.2 * beta2 / 2**64)
        self.Boo = int(6 * ((beta2 / (n * (k + ell)))**0.5))
        #   Boo_h = round(Boo/2^nuw)
        self.Boo_h = (self.Boo + (1 << (self.nuw - 1))) >> self.nuw

    def _check_bounds(self, h, z):
        """Check signature bounds. Return True iff bounds are acceptable."""

        #   this function only checks the norms; steps 1 and 2 are external.
        #   --- 1.  if |sig| != |sig|default return FAIL        [caller]
        #   --- 2.  (c hash, h, z) := sig                       [caller]

        midq = self.q // 2

        #   Infinity and L2 norms for hint
        h22 = 0
        hoo = 0
        for hi in h:
            for x in hi:
                hoo = max(hoo, abs(x))
                h22 += (x * x)

        #   Infinity norm and scaled L2 norm for z
        z22 = 0
        zoo = 0
        for zi in z:
            for x in zi:
                x = abs((x + midq) % self.q - midq)
                zoo = max(zoo, x)
                #   --- 6.  z2 := sum_i [ abs(zi) / 2^32 ]^2
                x >>= 32
                z22 += (x * x)

        #   --- 3:  if ||h||oo > round(Boo/2^nuw) return FAIL
        if  hoo > self.Boo_h:
            return False

        #   --- 4.  if ||z||oo > Boo return FAIL
        if  zoo > self.Boo:
            return False

        #   --- 5.  h2 := 2^(2*nuw - 64) * ||h||^2
        #   --- 7.  if (h2 + z2) > 2^-64*B22 return FAIL
        if  ((h22 << (2 * self.nuw - 64)) + z22) > self.B22:
            return False

        #   --- 8.  return OK
        return True

    def _decode(self, mp):
        """Decode(): Collapse shares into a single polynomial."""
        r = mp[0].copy()
        for p in mp[1:]:
            r = poly_add(r, p)
        return r

    def _zero_encoding(self):
        """ZeroEncoding(): Create a masked encoding of zero."""

        z = [ [0] * self.n for _ in range(self.d) ]
        i = 1
        #   same ops as with recursion, but using nested loops
        while i < self.d:
            for j in range(0, self.d, 2 * i):
                for k in range(j, j + i):
                    r = self.masking_poly()
                    z[k] = poly_add(z[k], r)
                    z[k + i] = poly_sub(z[k + i], r)
            i <<= 1
        return z

    def _lst_zero_encoding(self, e: int):
        """ZeroEncoding(): Create a masked encoding of zero for e copies."""

        z = [[ [0] * self.n for _ in range(self.d) ] for _ in range(e)]
        i = 1
        #   same ops as with recursion, but using nested loops
        while i < self.d:
            for j in range(0, self.d, 2 * i):
                for k in range(j, j + i):
                    r = self.masking_poly()
                    for idx in range(e):
                        z[idx][k] = poly_add(z[idx][k], r)
                        z[idx][k + i] = poly_sub(z[idx][k + i], r)
            i <<= 1
        return z

    def _refresh(self, v, z: list = None):
        """Refresh(): Refresh shares via ZeroEncoding."""
        if not z:
            z = self._zero_encoding()
        for i in range(self.d):
            v[i] = poly_add(v[i], z[i])

    def _lst_refresh(self, lst_v, idx_ell):
        """Refresh a specific share of all vectors in lst_v."""

        num_vecs = len(lst_v)
        if num_vecs == 0:
            return lst_v

        z = self._lst_zero_encoding(num_vecs)

        for idx in range(num_vecs):
            self._refresh(lst_v[idx][idx_ell], z[idx])

        return lst_v

    def _xof_sample_q(self, seed):
        """Expand a seed to n uniform values [0,q-1] using a XOF."""
        blen = (self.q_bits + 7) // 8
        mask = (1 << self.q_bits) - 1

        xof = SHAKE256.new(seed)
        v = [0] * self.n
        i = 0
        while i < self.n:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            if (x < self.q):
                v[i] = x
                i += 1
        return v

    def _expand_a(self, seed):
        """ExpandA(): Expand "seed" into a k*ell matrix A."""
        a = [[None for _ in range(self.ell)] for _ in range(self.k)]
        #   matrix rejection sampler
        for i in range(self.k):
            for j in range(self.ell):
                #   XOF( 'A' || row || col || seed )
                xof_in  = bytes([ord('A'), i, j, 0, 0, 0, 0, 0]) + seed
                a[i][j] = self._xof_sample_q(xof_in)
        return a

    def _xof_sample_u(self, seed, u):
        """Sample a keyed uniform noise polynomial."""
        blen = (u + 7) // 8
        mask = (1 << u) - 1
        mid = (1 << u) // 2
        xof = SHAKE256.new(seed)
        r = [0] * self.n
        for i in range(self.n):
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            x ^= mid        # two's complement sign (1=neg)
            r[i] = (x - mid) % self.q
        return r


    def _vec_add_rep_noise(self, v, u, rep):
        """Repeatedly add uniform noise to each share."""

        #   --- 1.  for i in [ |v| ] do
        for i in range(len(v)):

            #   --- 2.  for i_rep in [rep] do
            for i_rep in range(rep):

                #   --- 3. for j in [d] do
                for j in range(self.d):

                    #   --- 4.  rho <- {0,1}^lambda
                    sigma = self.random_bytes(self.sec)

                    #   --- 5.  hdr_u = ( 'u', rep, i, j, 0, 0, 0, 0 )
                    hdr_u   = bytes([ord('u'), i_rep, i, j,
                                            0, 0, 0, 0]) + sigma

                    #   --- 6.  v_i,j <- v_i,j + SampleU( hdr_u, sigma, u )
                    r       = self._xof_sample_u(hdr_u, u)
                    v[i][j] = poly_add(v[i][j], r)

                #   --- 7. Refresh([[v_i]])
                self._refresh(v[i])

        #   --- 8. Return [[v]]
        return v

    def _lst_vec_add_rep_noise(self, lst_v, u, rep):
        """Add noise to each share in a list of redundant vectors."""
        # Number of redundant copies (e.g. e = 2, 3, ...)
        num_vecs = len(lst_v)
        if num_vecs == 0:
            return lst_v  # nothing to do

        # Length of one vector (usually ell or k)
        vec_len = len(lst_v[0])

        # --- 1. for i in [ |v[0]| ] do
        for i in range(vec_len):

            # --- 2. for i_rep in [rep] do
            for i_rep in range(rep):

                # --- 3. for j in [d] do
                for j in range(self.d):

                    # --- 4.  rho <- {0,1}^lambda
                    sigma = self.random_bytes(self.sec)

                    # --- 5.  hdr_u = ( 'u', rep, i, j, 0, 0, 0, 0 ) || sigma
                    lst_hdr_u = [bytes([ord('u'), i_rep, i, j, 0, 0, 0, 0]) + sigma for _ in range(num_vecs)]

                    # --- 6.  v_i,j <- v_i,j + SampleU( hdr_u, u )
                    lst_r = [self._xof_sample_u(hdr_u, u) for hdr_u in lst_hdr_u]

                    # Add the same noise r to all redundant copies
                    for idx, r in zip(range(num_vecs), lst_r):
                        lst_v[idx][i][j] = poly_add(lst_v[idx][i][j], r)

                # --- 7. Refresh([[v_i]]) but shared across all copies

                self._lst_refresh(lst_v, i)

        # --- 8. Return [[v]]
        return lst_v

    def _chal_hash(self, mu, w):
        """Compute the challenge for the signature (a single hash)."""

        lqw = (self.q >> self.nuw).bit_length()
        blen = (lqw + 7) // 8       #   usually: 1 byte
        xof = SHAKE256.new()

        #   Hash w: XOF( 'h' || k || (0 pad) || mu || coeffs.. )
        xof.update(bytes([ord('h'), self.k, 0, 0, 0, 0, 0, 0]))
        xof.update(mu)  #   add mu

        if blen == 1:
            #   this is the typical case; just 1 byte per coefficient
            for i in range(self.k):
                xof.update(bytes(w[i]))
        else:
            #   general version where little‑endian encoding may be needed
            for i in range(self.k):
                for j in range(self.n):
                    xof.update(w[i][j].to_bytes(blen, byteorder=BYTEORDER))

        c_hash = xof.read(self.ch_sz)

        return c_hash

    def _chal_poly(self, c_hash):
        """ChalPoly(c_hash): Derive the challenge polynomial from c_hash."""
        mask_n  = (self.n - 1)

        #   For each sample, we need logn bits for the position and
        #   1 bit for the sign
        blen = (mask_n.bit_length() + 1 + 7) // 8

        xof = SHAKE256.new()
        xof.update(bytes([ord('c'), self.w, 0, 0, 0, 0, 0, 0]))
        xof.update(c_hash)

        #   Create a "w"‑weight ternary polynomial
        c_poly = [0] * self.n
        wt = 0
        while wt < self.w:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER)
            sign = x & 1
            idx = (x >> 1) & mask_n
            if (c_poly[idx] == 0):
                c_poly[idx] = (2 * sign - 1)
                wt += 1
        return c_poly

#   --- some testing code ----------------------------------------------

if (__name__ == "__main__"):

    def chksum(v, q=549824583172097,g=15,s=31337):
        """Simple recursive poly/vector/matrix checksum routine."""
        if isinstance(v, int):
            return ((g * s + v) % q)
        elif isinstance(v, list):
            for x in v:
                s = chksum(x,q=q,g=g,s=s)
        return s

    def chkdim(v, s=''):
        t = v
        while isinstance(t, list):
            s += '[' + str(len(t)) + ']'
            t = t[0]
        s += ' = ' + str(chksum(v))
        return s

    #   one instance here for testing
    # Note: RACC_Q and polyr functions must be defined for a full test.
    try:
        from polyr import RACC_Q
    except Exception:
        # Placeholder modulus
        RACC_Q = 549824583172097

    iut = Raccoon(  bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=4, ut=5,
                    uw=40, n=512, k=5, ell=4, w=19, d=8)

    #   initialize nist pseudo random
    entropy_input = bytes(range(48))
    drbg = NIST_KAT_DRBG(entropy_input)

    iut.set_random(drbg.random_bytes)
    iut.set_masking(MaskRandom().random_poly)

    print(f'name = {iut.name}')

    print("=== Keygen ===")
    msk, vk = iut.keygen_fault_attack_safe(4)
    print(chkdim(msk[1], 'key: t'))
    print(chkdim(msk[2], 'key: s'))

    print("=== Sign ===")
    mu = bytes(range(iut.mu_sz))
    lst_mu = [copy.deepcopy(mu) for _ in range(4)]

    # sig = iut.sign_mu(msk, mu)
    t = time.time()
    sig = iut.sign_mu_fault_attack_safe(msk, lst_mu, 4)
    print(time.time() - t)

    print("=== Verify ===")
    rsp = iut.verify_mu((vk[0][0], vk[1][0]), mu, (sig[i][0] for i in range(len(sig))))
    print(rsp)
    assert(rsp is True)