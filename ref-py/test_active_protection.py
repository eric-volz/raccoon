import types

from racc_api import NIST_Raccoon, RACC_Q
from racc_core import Raccoon


def test_verify_mu_active_matches_single_run():
    iut = NIST_Raccoon(bitsec=128, q=RACC_Q, nut=42, nuw=44, rep=8,
                       ut=6, uw=41, n=512, k=5, ell=4, w=19, d=1)
    msk, vk = iut.keygen()
    mu = bytes([1]) * iut.mu_sz
    sig = iut.sign_mu(msk, mu)

    assert iut.verify_mu_active(vk, mu, sig, k=2)


def test_verify_mu_active_detects_inconsistent_runs():
    dummy = object.__new__(Raccoon)

    def alternating(self, *_args, **_kwargs):
        alternating.counter += 1
        return (alternating.counter % 2) == 0

    alternating.counter = 0
    dummy._verify_mu_once = types.MethodType(alternating, dummy)

    assert dummy.verify_mu_active(None, None, None, k=1) is False
