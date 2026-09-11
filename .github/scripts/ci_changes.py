"""Classify NUL-delimited git paths for the PR check jobs."""
import sys


def classify(paths):
    frontend = rust = False
    for path in paths:
        if path.startswith((".github/workflows/", ".github/scripts/")):
            frontend = rust = True
        elif path.startswith(("apps/tauri/", "apps/server/", "crates/", ".cargo/")) or path in (
            "Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml", "rustfmt.toml", ".rustfmt.toml",
        ):
            rust = True
            # Tauri configuration also defines the frontend build integration.
            if path.startswith("apps/tauri/tauri.conf"):
                frontend = True
        elif path in ("Dockerfile", ".dockerignore") or path.startswith("docker-compose"):
            frontend = rust = True
        else:
            # Includes JS/TS, packages, tooling and docs checked by repository-wide Prettier.
            frontend = True
    return frontend, rust


if __name__ == "__main__":
    paths = sys.stdin.buffer.read().decode("utf-8", errors="surrogateescape").split("\0")
    frontend, rust = classify(path for path in paths if path)
    print(f"frontend={str(frontend).lower()}")
    print(f"rust={str(rust).lower()}")
