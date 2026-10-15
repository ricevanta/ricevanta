"""One admitted Cargo/rustc allowlist and one C toolchain rule (CI hardening section 6), shared by every consumer."""
from pathlib import Path
import unittest

import rust_env

ROOT = Path(__file__).resolve().parents[2]


class RustEnvTests(unittest.TestCase):
    def test_allowlist_is_the_section_6_table(self):
        self.assertEqual(rust_env.BOOTSTRAP_RUST_ENV, {'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_AUTO_INSTALL'})
        self.assertEqual(rust_env.FRESH_GO_RUST_ENV, {'CARGO_TARGET_DIR'})
        self.assertEqual(rust_env.WORKFLOW_RUST_ENV, {'CARGO_NET_OFFLINE', 'CARGO_INCREMENTAL', 'CARGO_TERM_COLOR', 'RUST_BACKTRACE'})
        self.assertEqual(rust_env.LOCAL_RUST_ENV, {'CARGO_HTTP_CAINFO'})
        self.assertEqual(rust_env.ADMITTED_RUST_ENV, rust_env.BOOTSTRAP_RUST_ENV | rust_env.FRESH_GO_RUST_ENV
                         | rust_env.WORKFLOW_RUST_ENV | rust_env.LOCAL_RUST_ENV)
        # Every other Cargo or Rust name, in any case, is refused: runner, linker, wrapper, compiler, rustdoc and flags.
        for name in ('RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTUP_TOOLCHAIN',
                     'CARGO_BUILD_RUSTC', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', 'rustflags', 'Cargo_Build_Target'):
            with self.subTest(name=name):
                self.assertEqual(rust_env.rust_overrides([name]), [name])
        self.assertEqual(rust_env.rust_overrides(sorted(rust_env.ADMITTED_RUST_ENV) + ['cargo_home', 'PATH', 'GOFLAGS']), [])

    def test_c_toolchain_names_follow_the_cc_crate_forms(self):
        refused = ['CC', 'cxx', 'AR', 'RANLIB', 'NVCC', 'CC_MASM_ASM', 'CFLAGS', 'CXXFLAGS', 'ARFLAGS', 'RANLIBFLAGS', 'CXXSTDLIB',
                   'CXXSTDLIB_STATIC', 'CC_x86_64-unknown-linux-gnu', 'CC_x86_64_unknown_linux_gnu', 'CFLAGS_aarch64_apple_darwin',
                   'HOST_CC', 'TARGET_CXX', 'host_cflags', 'TARGET_AR', 'AR_x86_64_pc_windows_msvc', 'CROSS_COMPILE', 'CRATE_CC_NO_DEFAULTS',
                   'CC_SHELL_ESCAPED_FLAGS', 'CC_FORCE_DISABLE', 'CC_PREFER_CLANG_CL_OVER_MSVC', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET',
                   'IPHONEOS_DEPLOYMENT_TARGET', 'VCINSTALLDIR', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_FFLAGS', 'CGO_LDFLAGS']
        for name in refused:
            with self.subTest(name=name):
                self.assertEqual(rust_env.c_toolchain_names([name]), [name])
        # The one exception, and names that only share a prefix without the separating underscore, stay admitted.
        self.assertEqual(rust_env.c_toolchain_names(['CC_ENABLE_DEBUG_OUTPUT', 'CCACHE_DIR', 'ARCH', 'CARGO_HOME', 'PATH', 'HOST_OS',
                                                    'TARGET_DIR', 'CGO_ENABLED', 'RANLIBX', 'GOFLAGS']), [])

    def test_consumers_import_the_one_definition(self):
        import bootstrap, check_policy, run_selected
        self.assertIs(run_selected.rust_env, rust_env)
        self.assertIs(check_policy.rust_env, rust_env)
        self.assertIs(bootstrap.rust_env, rust_env)
        for module in ('run_selected.py', 'check_policy.py', 'bootstrap.py'):
            with self.subTest(module=module):
                text = (ROOT / 'scripts/ci' / module).read_text(encoding='utf-8')
                for copy in ("'CARGO_NET_OFFLINE'", "'CARGO_TERM_COLOR'", "'RUST_BACKTRACE'", "'CARGO_HTTP_CAINFO'"):
                    self.assertNotIn(copy, text, f'{module} keeps its own copy of the allowlist')


if __name__ == '__main__':
    unittest.main()
