import json
import random
import time
import os
import hashlib
from typing import Any, Dict, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

from ref_py.racc_core import (
    Raccoon,
    RACC_Q,
    NIST_KAT_DRBG,
    MaskRandom,
    ConsistencyError,
)
from test_study.fault_injection import Fault


class ValidityError(Exception):
    pass


class Study:
    def __init__(
        self,
        filename: str,
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
        num_of_redundancy: int = 1,
        entropy_input: str = None,
    ):
        self.filename = filename
        self.num_of_redundancy = num_of_redundancy
        self.data: Dict[str, Any] = {}

        self.rac = Raccoon(
            bitsec=bitsec,
            q=q,
            nut=nut,
            nuw=nuw,
            rep=rep,
            ut=ut,
            uw=uw,
            n=n,
            k=k,
            ell=ell,
            w=w,
            d=d,
        )

        self.entropy_input: bytes = (
            bytes.fromhex(entropy_input) if entropy_input else bytes(range(48))
        )

        drbg = NIST_KAT_DRBG(self.entropy_input)
        random.seed(self.entropy_input)
        self.rac.set_random(drbg.random_bytes)
        self.rac.set_masking(MaskRandom().random_poly)

        self.lst_mu = [bytes(range(self.rac.mu_sz)) for _ in range(num_of_redundancy)]

    # ------------------------------------------------------------------
    # JSON helpers (merge-write, no truncation at start)
    # ------------------------------------------------------------------
    def _read_json_if_exists(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.filename):
            return None
        try:
            with open(self.filename, "r", encoding="utf-8") as f:
                txt = f.read().strip()
                if not txt:
                    return None
                return json.loads(txt)
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                Study._deep_update(dst[k], v)
            else:
                dst[k] = v

    def _atomic_write(self, obj: Dict[str, Any]) -> None:
        tmp = f"{self.filename}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, self.filename)

    def _merge_write_batch(self, runs_updates: Dict[str, Dict[str, Any]]) -> None:
        current = self._read_json_if_exists()
        if current is None:
            current = self.data

        current.setdefault("init", {}).setdefault("object", {})
        current.setdefault("study", {}).setdefault("runs", {})

        for run_id, upd in runs_updates.items():
            current["study"]["runs"].setdefault(run_id, {})
            self._deep_update(current["study"]["runs"][run_id], upd)

        self._atomic_write(current)
        self.data = current

    # ------------------------------------------------------------------
    # Study creation / loading
    # ------------------------------------------------------------------
    def generate_executions(
        self, num_runs: int, fault_probability: float, num_of_faults: int
    ) -> Dict[str, Any]:
        data = {
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
                    "num_of_redundancy": self.num_of_redundancy,
                    "entropy_input": self.entropy_input.hex(),
                }
            },
            "study": {
                "fault_probability": fault_probability,
                "num_runs": num_runs,
                "runs": {},
            },
        }

        for run in range(num_runs):
            fault = Fault.generate(fault_probability, num_of_faults)
            entry = {
                "successful": None,
                "has_error": fault is not None,
            }
            if fault:
                entry["fault_executions"] = fault.fault_executions
            data["study"]["runs"][str(run)] = entry

        self.data = data

        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False)

        return data

    @staticmethod
    def load_executions(filename: str) -> "Study":
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        study = Study(filename, **data["init"]["object"])
        study.data = data
        return study

    # ------------------------------------------------------------------
    # Deterministic per-run setup
    # ------------------------------------------------------------------
    @staticmethod
    def _derive_entropy(base: bytes, run_id: int) -> bytes:
        h1 = hashlib.sha256(base + run_id.to_bytes(8, "big")).digest()
        h2 = hashlib.sha256(h1).digest()
        return h1 + h2[:16]

    @classmethod
    def _build_rac_for_run(
        cls, init_obj: Dict[str, Any], run_id: int
    ) -> Tuple[Raccoon, list]:
        entropy = cls._derive_entropy(
            bytes.fromhex(init_obj["entropy_input"]), run_id
        )
        rac = Raccoon(
            bitsec=init_obj["bitsec"],
            q=init_obj["q"],
            nut=init_obj["nut"],
            nuw=init_obj["nuw"],
            rep=init_obj["rep"],
            ut=init_obj["ut"],
            uw=init_obj["uw"],
            n=init_obj["n"],
            k=init_obj["k"],
            ell=init_obj["ell"],
            w=init_obj["w"],
            d=init_obj["d"],
        )
        drbg = NIST_KAT_DRBG(entropy)
        random.seed(entropy)
        rac.set_random(drbg.random_bytes)
        rac.set_masking(MaskRandom().random_poly)

        lst_mu = [bytes(range(rac.mu_sz)) for _ in range(init_obj["num_of_redundancy"])]
        return rac, lst_mu

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    @staticmethod
    def _worker_execute_run(
        init_obj: Dict[str, Any], run_id: int, run_payload: Dict[str, Any]
    ) -> Tuple[int, Dict[str, Any]]:
        rac, lst_mu = Study._build_rac_for_run(init_obj, run_id)

        has_error = run_payload["has_error"]
        fault_attack = Fault(run_payload["fault_executions"]) if has_error else None

        start = time.time()
        successful = False
        valid = False
        rounding_removed_error = False
        expected_error = True
        error_msg = ""

        try:
            lst_msk, lst_vk = rac.keygen_fault_attack_safe(
                init_obj["num_of_redundancy"]
            )
            lst_sig = rac.sign_mu_fault_attack_safe(
                lst_msk,
                lst_mu,
                init_obj["num_of_redundancy"],
                fault_attack.inject if fault_attack else None,
            )
            valid = rac.verify_mu(
                (lst_vk[0][0], lst_vk[1][0]),
                lst_mu[0],
                (lst_sig[i][0] for i in range(len(lst_sig))),
            )
            successful = True
        except ConsistencyError as ex:
            error_msg = str(ex)
            if not has_error:
                raise ValidityError("Unexpected consistency error.")
        except Exception as ex:
            error_msg = str(ex)
            expected_error = False

        end = time.time()

        if has_error and successful:
            if valid:
                rounding_removed_error = True
            else:
                raise ValidityError(f"Invalid signature in run {run_id}")

        if not has_error and not valid:
            raise ValidityError(f"Verification failed in run {run_id}")

        if not expected_error:
            raise ValidityError(f"Unexpected failure in run {run_id}")

        result = {"successful": successful, "took_time": end - start}
        if has_error and not successful:
            result["expected_error"] = expected_error
            result["error_msg"] = error_msg
        elif has_error and successful:
            result["rounding_removed_error"] = rounding_removed_error

        return run_id, result

    # ------------------------------------------------------------------
    # Parallel execution with batch merge-write
    # ------------------------------------------------------------------
    def run_parallel(
        self, max_workers: Optional[int] = None, write_every: int = 50
    ) -> None:
        if not self.data:
            raise ValueError("No study loaded.")

        init_obj = self.data["init"]["object"]
        runs = self.data["study"]["runs"]

        pending_runs: Dict[str, Dict[str, Any]] = {}
        completed = 0

        with ProcessPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(
                    Study._worker_execute_run, init_obj, int(run_id), payload
                ): run_id
                for run_id, payload in runs.items()
            }

            for fut in as_completed(futures):
                run_id = futures[fut]
                _, result = fut.result()

                self.data["study"]["runs"][run_id].update(result)
                pending_runs[run_id] = result

                completed += 1
                if write_every > 0 and completed % write_every == 0:
                    self._merge_write_batch(pending_runs)
                    pending_runs.clear()

        if pending_runs:
            self._merge_write_batch(pending_runs)


if __name__ == "__main__":
    study = Study("study.json", num_of_redundancy=4)
    study.generate_executions(100, 0.9, 1)

    s = Study.load_executions("study.json")
    s.run_parallel(max_workers=None, write_every=10)
