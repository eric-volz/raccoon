import random


class Fault:
    FUNCTION_INVOCATIONS: int = 23

    def __init__(self, fault_executions: list[int]):
        if not 0 <= min(fault_executions) and max(fault_executions) < Fault.FUNCTION_INVOCATIONS:
            raise ValueError(f"Fault execution number needs to be between 0 and {Fault.FUNCTION_INVOCATIONS}")
        self.fault_executions: list = fault_executions
        self.number_of_calls: int = 0
        self.injected: int = 0
        self.error = None

    @staticmethod
    def generate(fault_probability: float, number_of_faults: int) -> "Fault" or None:
        if random.random() < fault_probability:
            return Fault([random.randint(0, Fault.FUNCTION_INVOCATIONS - 1) for _ in range(number_of_faults)])
        return None

    def _inject_recursive(self, entry: any, maximum = None) -> any:
        if isinstance(entry, list):
            inject_into = random.randint(0, len(entry) - 1)
            entry[inject_into] = self._inject_recursive(entry[inject_into], max(entry))
            return entry

        if isinstance(entry, bool):
            return False if entry is True else True

        if isinstance(entry, int):
            error: int = random.randint(1, maximum)
            entry += error
            self.error = error
            return entry

        if isinstance(entry, bytes):
            data = bytearray(entry)
            inject_into = random.randint(0, len(data) - 1)
            while True:
                r = random.getrandbits(8)
                if r != data[inject_into]:
                    data[inject_into] = r
                    self.error = r
                    break
            return bytes(data)

        raise KeyError("Could not inject error.")

    def inject(self, entry: any) -> bool:
        if self.number_of_calls in self.fault_executions:
            self._inject_recursive(entry)
            self.injected += 1
            self.number_of_calls += 1
            return True
        self.number_of_calls += 1
        return False


    def is_fully_injected(self) -> bool:
        return self.injected == len(self.fault_executions)
