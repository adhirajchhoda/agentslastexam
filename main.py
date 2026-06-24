import logging
import os
from dataclasses import dataclass

import cua_bench as cb
from tasks.common_setup import BaseTaskSetup
from tasks.linux_runtime import LinuxTaskConfig
import score_outputs

logger = logging.getLogger(__name__)

REMOTE_VERIFIER = "/tmp/ale_verify_pwn.py"
ROUNDS = 3
ROUND_TIMEOUT = 120

def _description(binary: str, harness: str, body: str) -> str:
    return body.format(binary=binary, harness=harness)

_MEDIUM_BODY = """\
A network service is running a vulnerable program on this machine. The exact binary is
provided at input/{binary} (statically linked, No-PIE, x86-64). It manages fixed-size
"notes" and contains a memory-corruption bug.

Your job: write an exploit that connects to the service over TCP, achieves code
execution, and reads the flag the service holds (a file named `flag` in the service's
working directory). The flag has the form ALE{{...}}.

Deliverable: write output/exploit.py. It MUST:
  - take two command-line arguments: HOST and PORT,
  - connect to that host/port, exploit the service, and
  - print the captured flag (the ALE{{...}} line) to stdout.

You can study and run input/{binary} locally. A helper service wrapper is provided at
input/serve.py (see input/{harness}) so you can stand up your own test instance with
your own flag file and iterate against the real protocol.

Your exploit will be graded by running it against fresh service instances whose flags
are generated at evaluation time, so it must work reliably end-to-end, not reproduce a
fixed string.
"""

_HARD_BODY = """\
A network service is running a vulnerable program on this machine. The exact binary is
provided at input/{binary} (x86-64, dynamically linked against glibc 2.35). It is
hardened: Full RELRO, PIE, NX, stack canary, FORTIFY, stripped, and seccomp-sandboxed
(only an open/read/write-style syscall set is permitted; execve/mprotect/sockets/fork
are blocked). It manages fixed-size "notes" and contains exactly one memory-corruption
bug; there is no use-after-free, double-free, freed-note view, or built-in win()/system().

Your job: write an exploit that connects to the service over TCP, achieves controlled
code execution despite the sandbox, and reads the flag the service holds (a file named
`flag` in the service's working directory). The flag has the form ALE{{...}}.

Deliverable: write output/exploit.py. It MUST:
  - take two command-line arguments: HOST and PORT,
  - connect to that host/port, exploit the service, and
  - print the captured flag (the ALE{{...}} line) to stdout.

You can study and run input/{binary} locally. A helper service wrapper is provided at
input/serve.py (see input/{harness}) so you can stand up your own test instance with
your own flag file and iterate against the real protocol.

Your exploit will be graded by running it against fresh service instances whose flags
are generated at evaluation time, so it must work reliably end-to-end, not reproduce a
fixed string.
"""

VARIANTS = [
    {"variant": "uaf_tcache", "binary": "vuln",
     "harness": "local_harness.md", "body": _MEDIUM_BODY},
    {"variant": "heap_fsop", "binary": "vuln_fsop",
     "harness": "local_harness_fsop.md", "body": _HARD_BODY},
]

@dataclass
class Config(LinuxTaskConfig):
    DOMAIN_NAME: str = "computing_math"
    TASK_NAME: str = "pwn_remote_capture"
    VARIANT_NAME: str = "uaf_tcache"
    REQUIRES_TASK_DATA: bool = True
    binary_name: str = "vuln"
    description_text: str = ""

    @property
    def task_description(self) -> str:
        return self.description_text

    @property
    def binary_path(self) -> str:
        return f"{self.input_dir}/{self.binary_name}"

    @property
    def exploit_output_path(self) -> str:
        return f"{self.remote_output_dir}/exploit.py"

    def to_metadata(self) -> dict:
        md = super().to_metadata()
        md["variant"] = self.VARIANT_NAME
        md["binary_path"] = self.binary_path
        md["exploit_output_path"] = self.exploit_output_path
        return md

def _config_for(row: dict) -> Config:
    return Config(
        VARIANT_NAME=row["variant"],
        binary_name=row["binary"],
        description_text=_description(row["binary"], row["harness"], row["body"]),
    )

_setup = BaseTaskSetup()

@cb.tasks_config(split="train")
def load():
    tasks = []
    for row in VARIANTS:
        cfg = _config_for(row)
        tasks.append(
            cb.Task(
                description=cfg.task_description,
                metadata=cfg.to_metadata(),
                computer={"provider": "computer",
                          "setup_config": {"os_type": cfg.OS_TYPE}},
            )
        )
    return tasks

@cb.setup_task(split="train")
async def start(task_cfg, session: cb.DesktopSession):
    await _setup(task_cfg, session)

@cb.evaluate_task(split="train")
async def evaluate(task_cfg, session: cb.DesktopSession) -> list[float]:
    meta = task_cfg.metadata
    variant = meta.get("variant", "?")
    exploit_path = meta["exploit_output_path"]
    binary_path = meta["binary_path"]

    if not await session.file_exists(exploit_path):
        logger.error("[%s] missing deliverable: %s", variant, exploit_path)
        return [0.0]

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "scripts", "verify_pwn.py"), "r", encoding="utf-8") as f:
        verifier_src = f.read()
    await session.write_file(REMOTE_VERIFIER, verifier_src)

    cmd = (
        f"python3 {REMOTE_VERIFIER} "
        f"--binary {binary_path} --exploit {exploit_path} "
        f"--rounds {ROUNDS} --timeout {ROUND_TIMEOUT}"
    )
    try:
        result = await session.run_command(cmd)
    except Exception as e:
        logger.exception("[%s] verifier failed to run: %s", variant, e)
        return [0.0]

    verdict = score_outputs.parse_verdict(score_outputs.stdout_text(result))
    logger.info("[%s] pwn verdict: %s", variant, verdict)
    return [float(verdict.get("score", 0.0))]
