import unittest

from ci_changes import classify


class ChangeDetectionTests(unittest.TestCase):
    def test_frontend_and_formatting_paths(self):
        for path in ["apps/frontend/src/app.tsx", "packages/ui/src/button.tsx", "pnpm-lock.yaml", "package.json", "docs/design.md", "AGENTS.md"]:
            with self.subTest(path=path):
                self.assertEqual(classify([path]), (True, False))

    def test_backend_paths(self):
        for path in ["apps/tauri/src/lib.rs", "apps/server/src/main.rs", "crates/core/src/lib.rs", "Cargo.lock", "Cargo.toml", ".cargo/config.toml"]:
            with self.subTest(path=path):
                self.assertEqual(classify([path]), (False, True))

    def test_shared_paths(self):
        for path in [".github/workflows/pr-check.yml", ".github/scripts/ci_changes.py", "Dockerfile", ".dockerignore", "apps/tauri/tauri.conf.json"]:
            with self.subTest(path=path):
                self.assertEqual(classify([path]), (True, True))

    def test_mixed_changes(self):
        self.assertEqual(classify(["apps/frontend/src/app.tsx", "crates/core/src/lib.rs"]), (True, True))

    def test_no_changes(self):
        self.assertEqual(classify([]), (False, False))


if __name__ == "__main__":
    unittest.main()
