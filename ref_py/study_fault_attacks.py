import json
import multiprocessing
import os
import queue
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from racc_core import Raccoon, RACC_Q, NIST_KAT_DRBG, MaskRandom, ConsistencyError


class FaultAttack:
    FUNCTION_INVOCATIONS: int = 21

    def __init__(self, has_error: bool, fault_invocation: Optional[int]):
        if not has_error and fault_invocation is not None:
            raise ValueError("Fault invocation can not be set if function has no error")
        self.has_error: bool = has_error
        self.fault_invocation: Optional[int] = fault_invocation
        self.invocations: int = 0
        self.injected: bool = False

    @staticmethod
    def generate(fault_probability: float) -> Tuple[bool, Optional[int]]:
        if random.random() < fault_probability:
            fault_invocation = random.randint(0, FaultAttack.FUNCTION_INVOCATIONS - 1)
            return True, fault_invocation
        return False, None

    @staticmethod
    def inject_recursive(entry: Any, maximum = None) -> Any:
        if isinstance(entry, list):
            inject_into = random.randint(0, len(entry) - 1)
            entry[inject_into] = FaultAttack.inject_recursive(entry[inject_into], max(entry[inject_into]))
            return entry

        if isinstance(entry, int):
            error: int = random.randint(1, maximum)
            entry += error
            return entry

        if isinstance(entry, bytes):
            data = bytearray(entry)
            inject_into = random.randint(0, len(data) - 1)
            data[inject_into] = random.getrandbits(8)
            return bytes(data)

        raise KeyError("Could not inject error.")

    def inject_error(self, lst: List[Any]) -> None:
        if self.injected:
            return

        if self.invocations == self.fault_invocation:
            entry_num = random.randint(0, len(lst) - 1)
            lst[entry_num] = self.inject_recursive(lst[entry_num])
            self.injected = True

        self.invocations += 1


class StudyFaultAttacks:
    """
    Study runner for fault attacks with optional parallel execution.
    """

    _WORKER_INSTANCE: Optional["StudyFaultAttacks"] = None

    def __init__(
        self,
        bitsec: int = 128,
        q: int = RACC_Q,
        nut: int = 42,
        nuw: int = 44,
        rep: int = 4,
        ut: int = 5,
        uw: int = 40,
        n: int = 512,
        k: int = 5,
        ell: int = 4,
        w: int = 19,
        d: int = 8,
        e: int = 1,
        entropy_input: Optional[str] = None,
    ):
        self.rac = Raccoon(
            bitsec=bitsec, q=q, nut=nut, nuw=nuw, rep=rep, ut=ut, uw=uw, n=n, k=k, ell=ell, w=w, d=d
        )
        self.e: int = e

        self.entropy_input: bytes = bytes.fromhex(entropy_input) if entropy_input else bytes(range(48))
        drbg = NIST_KAT_DRBG(self.entropy_input)

        self.rac.set_random(drbg.random_bytes)
        self.rac.set_masking(MaskRandom().random_poly)

        self.lst_mu: List[bytes] = [bytes(range(self.rac.mu_sz)) for _ in range(self.e)]
        self.lst_msk, self.lst_vk = self.rac.keygen_fault_attack_safe(self.e)

        random.seed(self.entropy_input)

        self.study_data: Dict[str, Any] = {}
        self.filename: Optional[str] = None

    # ---------------------------
    # Persistence / Study setup
    # ---------------------------

    def generate_executions(
        self,
        num_runs: int,
        fault_probability: float,
        write: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate study JSON data and optionally write to disk.
        """
        study_data: Dict[str, Any] = {
            "init": {
                "object": {
                    "bitsec": self.rac.bitsec,
                    "q": RACC_Q,
                    "nut": self.rac.nut,
                    "nuw": self.rac.nuw,
                    "rep": self.rac.rep,
                    "ut": self.rac.ut,
                    "uw": self.rac.uw,
                    "n": self.rac.n,
                    "k": self.rac.k,
                    "ell": self.rac.ell,
                    "w": self.rac.w,
                    "d": self.rac.d,
                    "e": self.e,
                    "entropy_input": self.entropy_input.hex(),
                }
            },
            "study": {
                "fault_probability": fault_probability,
                "num_runs": num_runs,
                "runs": {},
            },
        }

        runs: Dict[int, Dict[str, Any]] = {}
        for run in range(num_runs):
            has_error, fault_invocation = FaultAttack.generate(fault_probability)
            runs[run] = {
                "successful": None,
                "has_error": has_error,
                "fault_invocation": fault_invocation,
            }

        study_data["study"]["runs"] = runs
        self.study_data = study_data

        if not write:
            return study_data

        self.filename = self._default_filename()
        self._atomic_write_json(self.filename, self.study_data)
        return study_data

    @staticmethod
    def load_executions(filename: str) -> "StudyFaultAttacks":
        with open(filename, "r", encoding="utf-8") as f:
            study_data = json.load(f)

        study = StudyFaultAttacks(**study_data["init"]["object"])
        study.study_data = study_data
        study.filename = filename
        return study

    # ---------------------------
    # Execution
    # ---------------------------

    def single_execute(self, num_run: int, e: int) -> Dict[str, Any]:
        start_time = time.time()

        run: Dict[str, Any] = self.study_data["study"]["runs"][str(num_run)]
        fault_attack = FaultAttack(run["has_error"], run["fault_invocation"])

        successful = False
        error_msg = ""
        expected_error = True

        try:
            self.rac.sign_mu_fault_attack_safe(self.lst_msk, self.lst_mu, e, fault_attack.inject_error)
            successful = True
        except ConsistencyError as ex:
            error_msg = str(ex)
        except Exception as ex:
            error_msg = str(ex)
            expected_error = False

        end_time = time.time()

        result: Dict[str, Any] = {
            "successful": successful,
            "took_time": end_time - start_time,
        }

        if error_msg:
            result["error"] = error_msg
            result["expected_error"] = expected_error

        if fault_attack.has_error and not fault_attack.injected:
            raise RuntimeError(f"No error was injected: {num_run}")

        return result


def main() -> None:
    StudyFaultAttacks(e=2).generate_executions(1000, 0.9, True)

    study = StudyFaultAttacks.load_executions(
        os.path.join(os.path.dirname(__file__), "study_fault_attacks.json")
    )

    print(study.single_execute(0, 2))


if __name__ == "__main__":
    main()
