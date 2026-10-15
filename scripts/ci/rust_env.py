"""The one admitted Cargo and rustc environment and the C toolchain rule (CI hardening spec, section 6).

Standard library only: bootstrap.py runs under the runner's preinstalled Python. run_selected.py, check_policy.py and
bootstrap.py import these definitions; none keeps its own copy.
"""
import re

# Every name Cargo, rustc, rustup or rustdoc reads that could replace a runner, linker, wrapper, compiler or flags.
CONTROLLED = re.compile(r'^(?:CARGO|RUST)|RUSTFLAGS|RUSTDOCFLAGS')
# Section 6's table, by source.
BOOTSTRAP_RUST_ENV = frozenset({'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_AUTO_INSTALL'})
FRESH_GO_RUST_ENV = frozenset({'CARGO_TARGET_DIR'})
WORKFLOW_RUST_ENV = frozenset({'CARGO_NET_OFFLINE', 'CARGO_INCREMENTAL', 'CARGO_TERM_COLOR', 'RUST_BACKTRACE'})
# A developer's proxy CA bundle; CI fetches no crate through the wrapper.
LOCAL_RUST_ENV = frozenset({'CARGO_HTTP_CAINFO'})
ADMITTED_RUST_ENV = BOOTSTRAP_RUST_ENV | FRESH_GO_RUST_ENV | WORKFLOW_RUST_ENV | LOCAL_RUST_ENV


def rust_overrides(names):
    """Cargo or Rust names, matched case-insensitively, outside ADMITTED_RUST_ENV."""
    return sorted(n for n in names if CONTROLLED.search(n.upper()) and n.upper() not in ADMITTED_RUST_ENV)


# The cc crate reads these as <var>_<target>, <var>_<target_with_underscores>, HOST_<var>, TARGET_<var> and <var>.
C_TOOL_VARS = ('CC', 'CXX', 'AR', 'RANLIB', 'NVCC', 'CC_MASM_ASM', 'CFLAGS', 'CXXFLAGS', 'ARFLAGS', 'RANLIBFLAGS',
               'CXXSTDLIB', 'CXXSTDLIB_STATIC')
# Other cc and cgo switches, matched exactly; any *_DEPLOYMENT_TARGET name is matched by suffix.
C_EXACT = frozenset({'CROSS_COMPILE', 'CRATE_CC_NO_DEFAULTS', 'CC_SHELL_ESCAPED_FLAGS', 'CC_FORCE_DISABLE',
                     'CC_PREFER_CLANG_CL_OVER_MSVC', 'SDKROOT', 'VCINSTALLDIR', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS',
                     'CGO_FFLAGS', 'CGO_LDFLAGS'})
# Only makes cc log its invocations; agent.yml sets it for diagnosis.
C_ALLOWED = frozenset({'CC_ENABLE_DEBUG_OUTPUT'})


def is_c_toolchain_name(name):
    upper = name.upper()
    if upper in C_ALLOWED: return False
    if upper in C_EXACT or upper.endswith('_DEPLOYMENT_TARGET'): return True
    return any(upper == v or upper in ('HOST_' + v, 'TARGET_' + v) or upper.startswith(v + '_') for v in C_TOOL_VARS)


def c_toolchain_names(names):
    """Names, matched case-insensitively, that set a C compiler, archiver, flags or SDK for cc or cgo."""
    return sorted(n for n in names if is_c_toolchain_name(n))
