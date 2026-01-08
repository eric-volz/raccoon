import unittest
from unittest import mock

from nist_kat_drbg import NIST_KAT_DRBG
from mask_random import MaskRandom
from polyr import RACC_Q

import racc_core
from racc_core import Raccoon


"""
Test suite for the Raccoon redundant execution and fault injection mechanism.

What is tested:

1. _redundant_equal without any faults:
   - All redundant executions agree and the function returns the correct result.

2. _redundant_equal with a fixed number of injected faults:
   - When at least one redundant execution is corrupted, a RuntimeError
     with the message "Fault detected" is raised.

3. _inject_fault with too many faults:
   - If the configured number of faults exceeds the number of redundant
     executions (e), a ValueError is raised.

4. _inject_fault driving all results to zero:
   - If fault injection would make all redundant results equal to zero,
     a RuntimeError with "Unsafe exception ..." is raised.

5. _redundant_equal with probabilistic faults:
   - Using fault_probability and mocking random.random / random.randint,
     we ensure that faults are injected and _redundant_equal raises a
     RuntimeError ("Fault detected" or "Unsafe exception ...").

6. Integration: sign_mu and verify_mu without faults:
   - With fault injection disabled, sign_mu produces a valid signature and
     verify_mu returns True on that signature.

7. Integration: sign_mu with fixed faults:
   - With a fixed number of faults configured, sign_mu fails with a
     RuntimeError (either from _redundant_equal, _inject_fault, or the
     internal verification "Signature not valid").

8. Integration: sign_mu with probabilistic faults:
   - With fault_probability > 0 and mocked randomness to always trigger
     faults, sign_mu fails with a RuntimeError.
"""


class RaccoonFaultInjectionTests(unittest.TestCase):
    def setUp(self):
        # Deterministic randomness for reproducible tests
        entropy_input = bytes(range(48))
        drbg = NIST_KAT_DRBG(entropy_input)

        self.iut = Raccoon(
            bitsec=128,
            q=RACC_Q,
            nut=42,
            nuw=44,
            rep=4,
            ut=5,
            uw=40,
            n=512,
            k=5,
            ell=4,
            w=19,
            d=8,
            e=10,  # number of redundant executions
        )
        self.iut.set_random(drbg.random_bytes)
        self.iut.set_masking(MaskRandom().random_poly)

        # Default: no faults
        self.iut.set_faults(0)
        self.iut.set_fault_probability(0.0)

        # Keypair + example message
        self.msk, self.vk = self.iut.keygen()
        self.mu = b"Hallo"

    # ------------------------------------------------------------------
    # 1. Baseline: _redundant_equal without faults works correctly
    # ------------------------------------------------------------------
    def test_redundant_equal_no_faults(self):
        def plus_one(x):
            return x + 1

        self.iut.set_faults(0)
        self.iut.set_fault_probability(0.0)

        result = self.iut._redundant_equal(plus_one, 10)
        self.assertEqual(result, 11)

    # ------------------------------------------------------------------
    # 2. _redundant_equal with fixed faults => RuntimeError ("Fault detected")
    # ------------------------------------------------------------------
    def test_redundant_equal_with_fixed_faults_raises_runtimeerror(self):
        def plus_two(x):
            return x + 2

        # Force at least one result in the results array to become "0"
        self.iut.set_faults(1)
        self.iut.set_fault_probability(0.0)

        with self.assertRaises(RuntimeError) as ctx:
            self.iut._redundant_equal(plus_two, 5)
        self.assertIn("Fault detected", str(ctx.exception))

    # ------------------------------------------------------------------
    # 3. _inject_fault: faults > e => ValueError
    # ------------------------------------------------------------------
    def test_inject_fault_raises_valueerror_if_faults_too_large(self):
        self.iut.set_faults(self.iut.e + 1)
        self.iut.set_fault_probability(0.0)

        results = [1] * self.iut.e
        with self.assertRaises(ValueError):
            self.iut._inject_fault(results)

    # ------------------------------------------------------------------
    # 4. _inject_fault: all results become 0 => "Unsafe exception"
    # ------------------------------------------------------------------
    def test_inject_fault_all_zero_results_unsafe_exception(self):
        # faults = e => all positions will be set to 0
        self.iut.set_faults(self.iut.e)
        self.iut.set_fault_probability(0.0)

        results = [1] * self.iut.e
        with self.assertRaises(RuntimeError) as ctx:
            self.iut._inject_fault(results)
        self.assertIn("Unsafe exception", str(ctx.exception))

    # ------------------------------------------------------------------
    # 5. Fault probability: random.random / randint mocked
    # ------------------------------------------------------------------
    def test_redundant_equal_with_probability_faults(self):
        def times_two(x):
            return x * 2

        # faults = 0, but probability > random.random
        self.iut.set_faults(0)
        self.iut.set_fault_probability(0.5)

        # random.random -> 0.0 (always < 0.5 => fault branch is taken)
        # random.randint -> e (so we inject faults across all executions)
        with mock.patch("racc_core.random.random", return_value=0.0), \
             mock.patch("racc_core.random.randint", return_value=self.iut.e):

            with self.assertRaises(RuntimeError) as ctx:
                self.iut._redundant_equal(times_two, 7)

            msg = str(ctx.exception)
            self.assertTrue(
                "Fault detected" in msg
                or "Unsafe exception" in msg
            )

    # ------------------------------------------------------------------
    # 6. Integration: sign_mu + verify_mu without faults
    # ------------------------------------------------------------------
    def test_sign_and_verify_without_faults(self):
        self.iut.set_faults(0)
        self.iut.set_fault_probability(0.0)

        sig = self.iut.sign_mu(self.msk, self.mu)
        self.assertTrue(self.iut.verify_mu(self.vk, self.mu, sig))

    # ------------------------------------------------------------------
    # 7. Integration: sign_mu with fixed faults must fail
    # ------------------------------------------------------------------
    def test_sign_mu_with_fixed_faults_fails(self):
        self.iut.set_faults(1)
        self.iut.set_fault_probability(0.0)

        # We expect _redundant_equal (or the internal verification) to detect a fault
        with self.assertRaises(RuntimeError) as ctx:
            self.iut.sign_mu(self.msk, self.mu)

        # Could be a fault in _redundant_equal, an unsafe exception, or a failed internal verify
        self.assertTrue(
            "Fault detected" in str(ctx.exception)
            or "Unsafe exception" in str(ctx.exception)
            or "Signature not valid" in str(ctx.exception)
        )

    # ------------------------------------------------------------------
    # 8. Integration: sign_mu with probabilistic faults must fail
    # ------------------------------------------------------------------
    def test_sign_mu_with_probability_faults_fails(self):
        self.iut.set_faults(0)
        self.iut.set_fault_probability(0.5)

        with mock.patch("racc_core.random.random", return_value=0.0), \
             mock.patch("racc_core.random.randint", return_value=self.iut.e):

            with self.assertRaises(RuntimeError) as ctx:
                self.iut.sign_mu(self.msk, self.mu)

        self.assertTrue(
            "Fault detected" in str(ctx.exception)
            or "Unsafe exception" in str(ctx.exception)
            or "Signature not valid" in str(ctx.exception)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
