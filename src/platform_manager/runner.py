"""The only place this tool starts other programs.

Commands are always argument lists and never go through a shell, so values
from config or API responses can't inject shell syntax. Tests swap in a fake
runner instead of calling aws, kubectl or gh.
"""

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Result:
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self):
        return self.code == 0 and not self.timed_out

    @property
    def output(self):
        return f"{self.stdout}\n{self.stderr}".strip()


class Runner:
    def run(self, args, timeout=20, env=None):
        if not isinstance(args, list | tuple) or not args:
            raise TypeError("Runner.run needs a non-empty argument list")
        if shutil.which(args[0]) is None:
            return Result(127, "", f"{args[0]}: command not found")
        try:
            p = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            return Result(124, exc.stdout or "", exc.stderr or "", timed_out=True)
        return Result(p.returncode, p.stdout, p.stderr)

    def interactive(self, args, env=None):
        """Run with the user's terminal attached, for login flows that open a browser or prompt."""
        if shutil.which(args[0]) is None:
            return 127
        return subprocess.run(list(args), env=env).returncode
