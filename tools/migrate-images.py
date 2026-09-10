#!/usr/bin/env python3
"""Copy post images out of absolute Windows paths into public/ and rewrite refs.

Run from the project root:  python tools/migrate-images.py
Idempotent: refs already starting with /images/ are skipped.
"""
import os
import re
import shutil
import sys

POSTS_DIR = "pages/posts"
PUBLIC_DIR = os.path.join("public", "images", "posts")

# ![alt](path)  ->  groups: prefix, path, suffix
REF_RE = re.compile(r"(!\[[^\]]*\]\()([^)]+)(\))")


def resolve(raw: str):
    """Return a local filesystem path if the file exists on disk, else None.

    Post refs are absolute Windows paths (C:\\Users\\...); backslashes are
    normalised because the migration script runs under Git Bash on Windows.
    """
    p = raw.replace("\\", "/")
    return p if os.path.isfile(p) else None


def main() -> int:
    copied = rewritten = skipped = unresolved = 0

    for name in sorted(os.listdir(POSTS_DIR)):
        if not name.endswith(".md"):
            continue
        slug = name[: -len(".md")]
        md_path = os.path.join(POSTS_DIR, name)
        text = open(md_path, encoding="utf-8").read()
        out_dir = os.path.join(PUBLIC_DIR, slug)
        counter = 0

        def repl(m):
            nonlocal copied, rewritten, skipped, unresolved, counter
            prefix, raw, suffix = m.group(1), m.group(2), m.group(3)

            if raw.startswith("/images/") or raw.startswith("http"):
                skipped += 1
                return m.group(0)

            src = resolve(raw)
            if src is None:
                unresolved += 1
                print(f"  UNRESOLVED {slug}: {raw}")
                return m.group(0)  # left for manual handling in step 3

            counter += 1
            ext = os.path.splitext(src)[1].lower() or ".png"
            fname = f"{counter:02d}{ext}"
            os.makedirs(out_dir, exist_ok=True)
            shutil.copy2(src, os.path.join(out_dir, fname))
            copied += 1
            rewritten += 1
            return f"{prefix}/images/posts/{slug}/{fname}{suffix}"

        new_text = REF_RE.sub(repl, text)
        if new_text != text:
            open(md_path, "w", encoding="utf-8", newline="\n").write(new_text)
            print(f"{slug}: rewrote {counter} refs -> {out_dir}")

    print(
        f"\ncopied={copied} rewritten={rewritten} "
        f"skipped={skipped} unresolved={unresolved}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
