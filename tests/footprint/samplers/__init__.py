"""External process samplers for the footprint harness, one module per OS.

Each OS module exposes METRIC, DESCRIPTOR_KIND, a Sampler class bound to one
process, sample(pid), environment() and preflight(). Every module imports on
every OS; native libraries are loaded only when a sampler is used. A failed
read raises SamplerError, never returns a zero value
(docs/specs/footprint-harness.md section 2).
"""

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    footprint_bytes: int
    footprint_metric: str
    cpu_ns: int
    threads: int
    descriptors: int
    descriptor_kind: str


class SamplerError(Exception):
    """One sample could not be taken; the harness records a failed sample."""


class PreflightError(SamplerError):
    """The sampler cannot work on this host at all."""


def current():
    """The sampler module for the running OS."""
    if sys.platform == "linux":
        from samplers import linux

        return linux
    if sys.platform == "darwin":
        from samplers import darwin

        return darwin
    if sys.platform == "win32":
        from samplers import windows

        return windows
    raise PreflightError(f"unsupported platform {sys.platform}")
