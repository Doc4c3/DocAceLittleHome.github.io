# Blog Reframe onto Valaxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-written static site at `https://doc4c3.github.io/DocAceLittleHome.github.io/` with the Valaxy site in this repo, keeping the same URL, without downtime, and port the old site's dark identity onto the Yun theme.

**Architecture:** Valaxy 1.0.0-rc.9 + `valaxy-theme-yun`, built to static HTML by `pnpm build --ssg`. Source lives on `main`; the built site is published to a `gh-pages` branch that GitHub Pages serves at the repo subpath. Because the repo name does not match the account name, this is a **project site** and requires `vite.base = '/DocAceLittleHome.github.io/'` — without it every asset 404s. Theming is done through CSS custom properties the theme already exposes, plus one digits-only `@font-face` using `unicode-range`.

**Tech Stack:** Valaxy 1.0.0-rc.9, valaxy-theme-yun 1.0.0-rc.9, Vite 8, pnpm 10.33.0, Node 24.16.0, SCSS, GitHub Actions + peaceiris/actions-gh-pages.

**Spec:** `docs/superpowers/specs/2026-09-10-valaxy-blog-reframe-design.md`

## Global Constraints

Every task's requirements implicitly include all of these. Values are copied verbatim from the spec.

- **Live URL:** `https://doc4c3.github.io/DocAceLittleHome.github.io/`
- **`vite.base`:** `/DocAceLittleHome.github.io/` — leading *and* trailing slash. `siteConfig.url` is a different field and does not replace it.
- **Identity:** `title: "DA's BLOG"`, `subtitle: "mostly about CTFs and hacking"`, `description: "CTFer(misc and web) and SRC researcher"`, `lang: 'zh-CN'`, `timezone: 'Asia/Hong_Kong'`, `mode: 'dark'`
- **Author:** name `DocAcer`, email `1255893218@qq.com`, link `https://github.com/Doc4c3`, avatar `/images/avatar.png`
- **Categories:** exactly three, site-wide — `CTF`, `SRC`, `Learning`. Competition names live in `tags`, never in `categories`.
- **Colours:** background `#000`; theme primary `#FFC0CB`; hero name colour `#fff`
- **Typography:** digits from `Bender.otf` via a `unicode-range: U+0030-0039` face placed **first** in the stack; Latin from Novecento (one family name, explicit `font-weight: 400` and `700`); CJK from the system stack `'Microsoft YaHei', 'PingFang SC', 'Hiragino Sans GB', 'Noto Sans CJK SC'`.
- **Slugs are frozen** (published URLs): `shanghai-2025`, `wanqubei-2025`, `greatwall-5`, `ycb-2025`, `gaoxiao-2025`, `pengcheng-2025`, `pwn-basics`, `pangushi-da`, `wanqubei-2026`, `usb-keyboard-traffic`
- **Dates are frozen** (author-confirmed 2026-09-10): see the table in Task 1.
- **Old repo (read-only source of assets):** `Doc4c3/DocAceLittleHome.github.io`, branch `main`, raw base `https://raw.githubusercontent.com/Doc4c3/DocAceLittleHome.github.io/main/`
- **Safety:** nothing is pushed to GitHub without the user explicitly confirming first. See Tasks 8 and 9.

### Note on verification style

This project has **no test framework and no test files**. Per its contributing conventions, do not add a test scaffold just for this work. Every task therefore ends with a real, runnable check: a build, an assertion against built artifacts in `dist/`, or a live HTTP request. Where a task cannot yet produce a green build, it says so explicitly and gives a narrower check instead.

### Current baseline is RED

`pnpm build` **fails today**. Confirmed causes, both fixed by Tasks 1–3:

1. `[PARSE_ERROR] '0'-prefixed octal literals and octal escape sequences are deprecated` — one per Windows-backslash image path. Markdown image paths compile into JS `import` statements, so `\1`, `\U` inside `C:\Users\...` are read as JS escapes. All **62 refs across 7 posts**. `dist/` currently contains only `feed.xml` and no `index.html`.
2. `TypeError: Cannot read properties of undefined (reading 'replace')` in `xml-js` `writeCdata`, from `feed` generating RSS in the `build:after` hook. Probably a cascade from failure 1; re-check after it is fixed.

### Shell notes for the verification commands

This project lives in a Chinese-named directory and runs under Git Bash on
Windows. Two things bite:

- **Prefer a temp script file over a `<<'PY'` heredoc** for any Python check
  containing backslashes. Backslash sequences inside heredocs have already
  been observed to arrive mangled and raise `re.error: unterminated
  subpattern`. Write the script with the Write tool, run it, delete it.
- **Quote every path** and be aware that `git` reports paths in the
  `C:/...` form while the shell uses `/c/...`. When a command needs to print
  or match Chinese filenames, expect mojibake in captured output; match on
  the ASCII parts (slugs, counts) instead of on the Chinese text.

---

## File Structure

| Path | Responsibility |
|---|---|
| `site.config.ts` | Site identity: url, title, description, timezone, author, social. No layout concerns. |
| `valaxy.config.ts` | Build-level config: `vite.base`, active theme, theme config (`colors`, `bg_image`, `banner`, nav). |
| `styles/css-vars.scss` | Theme variable overrides — colours only. |
| `styles/index.scss` | `@font-face` declarations and font stacks. |
| `pages/posts/*.md` | Content. One file per post; slug is the filename. |
| `pages/links/index.md` | The friend/useful-links page. |
| `pages/about/index.md` | Author bio. |
| `locales/zh-CN.yml` | UI strings. |
| `public/images/posts/<slug>/` | One folder of images per post, ASCII-numbered. |
| `public/fonts/` | The three bundled fonts. |
| `public/bg.webp` | Background image. |
| `.github/workflows/gh-pages.yml` | CI: build and publish to `gh-pages`. |
| `tools/migrate-images.py` | One-shot migration helper (Task 2). Kept in-repo so the transformation is auditable. |

---

### Task 1: Rename posts to ASCII slugs and add frontmatter

Fixes the RSS crash cause (posts with no `date`/`title`) and removes the bracket routing defect. No build is expected to pass yet, so verification is by file assertion.

**Files:**
- Rename + modify: `pages/posts/*.md` (9 files)
- Create: none

**Interfaces:**
- Consumes: nothing.
- Produces: post files named exactly as the frozen slugs in Global Constraints. Task 2 depends on these filenames; Task 3's route assertion depends on them.

- [ ] **Step 1: Rename the nine files**

Run from the project root:

```bash
cd pages/posts
mv "第十届上海市大学生网络安全大赛WriteUp.md" shanghai-2025.md
mv "湾区杯.md"                                 wanqubei-2025.md
mv "第五届长城杯.md"                            greatwall-5.md
mv "ycb2025wp.md"                              ycb-2025.md
mv "2025高校网络安全管理运维赛.md"              gaoxiao-2025.md
mv "鹏城杯2025.md"                             pengcheng-2025.md
mv "PWN的学习日志-基础术语.md"                   pwn-basics.md
mv "盘古石-DA.md"                              pangushi-da.md
mv "[湾区杯2026]记录一下.md"                    wanqubei-2026.md
```

Plain `mv`, **not** `git mv`. Nothing under `pages/` is tracked yet (`git ls-files pages/` returns 0), so `git mv` fails with `not under version control` on every one of these. Step 4's `git add pages/posts` picks up the renames as additions.

The rename of `[湾区杯2026]记录一下.md` is **required**, not cosmetic: the square brackets parse as a Vue Router dynamic parameter and produce the broken route `/posts/:湾区杯2026%E8%AE%B0%E5%BD%95%E4%B8%80%E4%B8%8B`.

- [ ] **Step 2: Replace the frontmatter on every post**

Each file gets this block inserted at the very top, replacing any existing frontmatter. Use exactly these values:

`shanghai-2025.md`
```yaml
---
title: 第十届上海市大学生网络安全大赛WriteUp
date: 2025-08-06
categories:
  - CTF
tags:
  - 上海市赛
  - misc
---
```

`wanqubei-2025.md`
```yaml
---
title: 湾区杯
date: 2025-09-08
categories:
  - CTF
tags:
  - 湾区杯
  - forensics
---
```

`greatwall-5.md`
```yaml
---
title: 第五届长城杯
date: 2025-09-14
categories:
  - CTF
tags:
  - 长城杯
  - ai
---
```

`ycb-2025.md`
```yaml
---
title: 羊城杯2025
date: 2025-10-11
categories:
  - CTF
tags:
  - 羊城杯2025
  - ai
  - crypto
---
```

`gaoxiao-2025.md`
```yaml
---
title: 2025高校网络安全管理运维赛
date: 2025-10-20
categories:
  - CTF
tags:
  - 高校赛
  - forensics
---
```

`pengcheng-2025.md`
```yaml
---
title: 鹏城杯2025
date: 2025-12-13
categories:
  - CTF
tags:
  - 鹏城杯2025
  - misc
---
```

`pwn-basics.md`
```yaml
---
title: PWN的学习日志（2026/1/27）
date: 2026-01-27
categories:
  - CTF
tags:
  - pwn
---
```

`pangushi-da.md`
```yaml
---
title: 盘古石-DA 计算机取证
date: 2026-05-10
categories:
  - CTF
tags:
  - 盘古石
  - forensics
---
```

`wanqubei-2026.md` — this one already has frontmatter; **replace it entirely**, dropping the ctf-swarm-only keys (`ctf`, `difficulty`, `points`, `flag_format`, `author`), which Valaxy ignores:
```yaml
---
title: 湾区杯2026 总体 WP
date: 2026-09-04
categories:
  - CTF
tags:
  - 湾区杯2026
  - misc
  - web
  - pwn
  - re
  - crypto
---
```

The `pangushi-da.md` title deliberately differs from its H1 (`计算机取证`), which is too generic to identify the post. Also rewrite that post's H1 to match:

```markdown
# 盘古石-DA 计算机取证
```

- [ ] **Step 3: Verify filenames and frontmatter**

```bash
cd pages/posts
echo "--- non-ASCII filenames (expect none) ---"
ls | grep -P '[^\x00-\x7F]' || echo "OK: all ASCII"
echo "--- posts missing a date field (expect none) ---"
for f in *.md; do grep -q '^date:' "$f" || echo "MISSING DATE: $f"; done
echo "--- posts missing categories (expect none) ---"
for f in *.md; do grep -q '^categories:' "$f" || echo "MISSING CATEGORIES: $f"; done
echo "--- file count (expect 9) ---"
ls *.md | wc -l
```

Expected: `OK: all ASCII`, no `MISSING` lines, count `9`.

- [ ] **Step 4: Commit**

```bash
git add pages/posts
git commit -m "content: rename posts to ASCII slugs and add frontmatter

Fixes the bracket-derived dynamic route on the 湾区杯2026 post and gives
every post the title/date/categories the RSS generator needs."
```

---

### Task 2: Migrate images into `public/` and rewrite all references

This is what clears the `[PARSE_ERROR]` and makes a build possible.

**Files:**
- Create: `tools/migrate-images.py`, `public/images/posts/<slug>/NN.<ext>` (61 files)
- Modify: `pages/posts/*.md` (7 files with images), `shanghai-2025.md` (the lost-image placeholder)

**Interfaces:**
- Consumes: the slugs from Task 1.
- Produces: image files at `public/images/posts/<slug>/NN.<ext>` and markdown refs of the form `![alt](/images/posts/<slug>/NN.png)`. Task 3's build depends on there being zero backslash refs.

- [ ] **Step 1: Write the migration script**

Create `tools/migrate-images.py`:

```python
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
```

- [ ] **Step 2: Run it**

```bash
python tools/migrate-images.py
```

Expected: seven `rewrote N refs` lines summing to **61**, and a summary of `copied=61 rewritten=61 skipped=0 unresolved=1`. The single `unresolved` is the lost WeChat image in `shanghai-2025.md`, handled next.

- [ ] **Step 3: Replace the one unrecoverable reference**

`shanghai-2025.md` contains a reference to a WeChat temp file that no longer exists anywhere:
`87fa1e7675cf88f9b93434fff86853c0.jpg`. It is **not** recoverable from the old repo — the old repo's `微信图片_20250514131630.jpg` belongs to the USB writeup, a different post. Replace that whole image line with a visible note rather than shipping a broken `<img>`:

```markdown
> 图片缺失：原图为微信临时文件，已被清理，无法恢复。
```

- [ ] **Step 4: Verify no backslash refs remain and every ref resolves**

```bash
echo "--- remaining backslash refs (expect 0) ---"
grep -rc '](C:' pages/posts/ | grep -v ':0' || echo "OK: none"

echo "--- every markdown image ref resolves to a file (expect no MISSING) ---"
python - <<'PY'
import re, glob, os
bad = 0
for f in sorted(glob.glob("pages/posts/*.md")):
    txt = open(f, encoding="utf-8").read()
    for ref in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", txt):
        if ref.startswith("http"):
            continue
        p = os.path.join("public", ref.lstrip("/"))
        if not os.path.isfile(p):
            print(f"  MISSING {f}: {ref}")
            bad += 1
print(f"unresolved refs: {bad}")
PY

echo "--- images on disk (expect 61) ---"
find public/images/posts -type f | wc -l
```

Expected: `OK: none`, `unresolved refs: 0`, `61`.

Note the `os.path.join("public", ...)` in the ref check. The refs are web-root-absolute (`/images/...`), which maps to `public/images/...` on disk — `public/` *is* the web root. Checking `ref.lstrip("/")` directly against the filesystem resolves to a non-existent `<root>/images/...` and reports all 61 refs as unresolved regardless of whether the migration worked. Do not "fix" this line by moving the images.

- [ ] **Step 5: Commit**

```bash
git add tools/migrate-images.py public/images pages/posts
git commit -m "content: migrate post images into public/ and rewrite refs

Windows absolute paths compiled into JS imports and broke the build with
octal-escape parse errors. Refs are now root-absolute for the subpath base.
One image was a deleted WeChat temp file and is marked missing."
```

---

### Task 3: Site identity, base path, and the first green build

**Files:**
- Modify: `site.config.ts` (whole file), `valaxy.config.ts` (whole file)

**Interfaces:**
- Consumes: Tasks 1–2 (clean refs and frontmatter) — the build cannot go green before them.
- Produces: a green `pnpm build` and a valid `dist/`. Every later task re-runs this build.

- [ ] **Step 1: Rewrite `site.config.ts`**

```ts
import { defineSiteConfig } from 'valaxy'

export default defineSiteConfig({
  url: 'https://doc4c3.github.io/DocAceLittleHome.github.io/',
  lang: 'zh-CN',
  title: "DA's BLOG",
  subtitle: 'mostly about CTFs and hacking',
  description: 'CTFer(misc and web) and SRC researcher',
  timezone: 'Asia/Hong_Kong',
  mode: 'dark',
  author: {
    name: 'DocAcer',
    email: '1255893218@qq.com',
    link: 'https://github.com/Doc4c3',
    avatar: '/images/avatar.png',
  },
  social: [
    {
      name: 'RSS',
      link: '/atom.xml',
      icon: 'i-ri-rss-line',
      color: 'orange',
    },
    {
      name: 'GitHub',
      link: 'https://github.com/Doc4c3',
      icon: 'i-ri-github-line',
      color: '#6e5494',
    },
    {
      name: '哔哩哔哩',
      link: 'https://space.bilibili.com/498295819',
      icon: 'i-ri-bilibili-line',
      color: '#FF8EB3',
    },
    {
      name: 'E-Mail',
      link: '1255893218@qq.com',
      icon: 'i-ri-mail-line',
      color: '#8E71C1',
    },
  ],

  search: {
    enable: false,
  },
})
```

`url` and `vite.base` are different fields: `url` is the canonical/permalink URL used by SSG and RSS, `base` is the asset prefix. Setting only one yields a site that loads with dead links.

- [ ] **Step 2: Rewrite `valaxy.config.ts`**

```ts
import type { UserThemeConfig } from 'valaxy-theme-yun'
import { defineValaxyConfig } from 'valaxy'

// add icons what you will need
const safelist = [
  'i-ri-home-line',
]

/**
 * User Config
 */
export default defineValaxyConfig<UserThemeConfig>({
  // site config see site.config.ts

  // This repo is a GitHub Pages *project* site (repo name != account name),
  // so it is served from a subpath and every asset needs this prefix.
  // Both leading and trailing slashes are required.
  vite: {
    base: '/DocAceLittleHome.github.io/',
  },

  theme: 'yun',

  themeConfig: {
    type: 'nimbo',

    banner: {
      enable: true,
      title: "DA's BLOG",
    },

    colors: {
      primary: '#FFC0CB',
    },

    bg_image: {
      enable: true,
      url: '/bg.webp',
      dark: '/bg.webp',
      opacity: 0.15,
    },

    pages: [
      {
        name: '链接',
        url: '/links',
        icon: 'i-ri-link',
        color: 'dodgerblue',
      },
    ],
  },

  unocss: { safelist },
})
```

This replaces the scaffold's nav entry, which pointed at an external `decimo.top` domain. `bg.webp` is created in Task 4; until then the build still succeeds and the image simply 404s in a browser.

- [ ] **Step 3: Run the build — first green build**

```bash
NODE_OPTIONS=--max-old-space-size=4096 pnpm build
```

Expected: exits 0 and prints a build summary.

If it still fails, there are exactly two known causes to check:
- still a backslash path → `grep -rn '](C:' pages/posts/` should be empty
- a post missing `date` → the Task 1 step-3 assertion should have caught this
- the `xml-js` `writeCdata` error recurring means a post still has an undefined field the feed needs; inspect that post's frontmatter

- [ ] **Step 4: Verify the base path took effect**

```bash
echo "--- dist exists ---"; ls dist | head
echo "--- index.html references the subpath base (expect matches) ---"
grep -o '/DocAceLittleHome.github.io/assets/[^"]*' dist/index.html | head -3
echo "--- built post pages (expect 9) ---"
find dist/posts -name 'index.html' | wc -l
echo "--- NO route may contain a colon (expect none) ---"
find dist/posts -type d | grep ':' || echo "OK: no dynamic-param routes"
```

Expected: `dist/index.html` exists; at least one `/DocAceLittleHome.github.io/assets/...` match; **9** built post pages; `OK: no dynamic-param routes`.

- [ ] **Step 5: Commit**

```bash
git add site.config.ts valaxy.config.ts
git commit -m "feat: set site identity and the project-site base path

Repo name does not match the account, so Pages serves a subpath and
vite.base is required or every asset 404s. Replaces scaffold placeholders."
```

---

### Task 4: Dark theme — colours, background, and typography

**Files:**
- Create: `public/fonts/Bender.otf`, `public/fonts/Novecento-Wide-Bold.otf`, `public/fonts/Novecento-wide-Normal.ttf`, `public/bg.webp`
- Modify: `styles/css-vars.scss`, `styles/index.scss`

**Interfaces:**
- Consumes: `valaxy.config.ts` from Task 3, which already references `/bg.webp`.
- Produces: the visual identity. No later task depends on these internals.

- [ ] **Step 1: Fetch the fonts from the old repo**

Font files exist only in the old repo — they are not on local disk.

```bash
mkdir -p public/fonts
RAW=https://raw.githubusercontent.com/Doc4c3/DocAceLittleHome.github.io/main
curl -fsSL -o public/fonts/Bender.otf                  "$RAW/font/Bender.otf"
curl -fsSL -o public/fonts/Novecento-Wide-Bold.otf    "$RAW/font/Novecento-Wide-Bold-2.otf"
curl -fsSL -o public/fonts/Novecento-wide-Normal.ttf  "$RAW/font/Novecento-wide-Normal-2.ttf"
ls -la public/fonts
```

Expected sizes: `Bender.otf` 52536, `Novecento-Wide-Bold.otf` 47080, `Novecento-wide-Normal.ttf` 50388. If a download returns 0 bytes, retry — this host intermittently resets the connection.

- [ ] **Step 2: Fetch and convert the background image**

```bash
curl -fsSL -o /tmp/bg.png "$RAW/8f8a8af6d4afbc463b4b43460df474493d0c6123.png"
ls -la /tmp/bg.png          # expect 5450126 bytes
```

Convert to WebP. Try in this order and use the first that works:

```bash
# 1) ffmpeg
ffmpeg -y -i /tmp/bg.png -quality 82 public/bg.webp
# 2) ImageMagick
magick /tmp/bg.png -quality 82 public/bg.webp
# 3) Python Pillow (ephemeral, no install into the project)
uv run --with pillow python -c "from PIL import Image; Image.open('/tmp/bg.png').convert('RGB').save('public/bg.webp', 'WEBP', quality=82)"
```

Verify the result is dramatically smaller than 5.45 MB:

```bash
ls -la public/bg.webp
```

Expected: on the order of a few hundred KB. If WebP tooling is unavailable entirely, fall back to a resized PNG (`magick /tmp/bg.png -resize 1920x public/bg.png`), update the two `bg_image.url` / `bg_image.dark` values in `valaxy.config.ts` to `/bg.png`, and record the resulting size.

- [ ] **Step 3: Paint the dark colours in `styles/css-vars.scss`**

```scss
// Overrides for valaxy-theme-yun. The theme's own dark values are
// --va-c-bg: #1a1a1d and --va-c-bg-soft: #121215; the old site was pure black.
html.dark {
  --va-c-bg: #000;
  --va-c-bg-soft: #0a0a0a;
  --va-c-bg-mute: #111;
  --va-c-bg-light: #1a1a1a;
  --yun-nav-bg-color: rgb(0 0 0 / 0.8);
}
```

- [ ] **Step 4: Declare the fonts in `styles/index.scss`**

```scss
// --- Typography -----------------------------------------------------------
// Bender supplies digits ONLY. CSS font fallback is first-match-wins per
// glyph, so a digits-only face must come first in the stack; otherwise
// Novecento (which also contains digits) would claim them.
@font-face {
  font-family: 'Bender Digits';
  src: url('/fonts/Bender.otf') format('opentype');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
  unicode-range: U+0030-0039; // 0-9
}

// The two Novecento files declare DIFFERENT embedded family names
// ("Novecento wide" and "Novecento wide Normal"), so we assign one family
// name ourselves with explicit weights. Do not rely on the embedded names.
@font-face {
  font-family: 'Novecento Wide';
  src: url('/fonts/Novecento-wide-Normal.ttf') format('truetype');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Novecento Wide';
  src: url('/fonts/Novecento-Wide-Bold.otf') format('opentype');
  font-weight: 700;
  font-style: normal;
  font-display: swap;
}

// None of the bundled fonts contain any CJK glyphs, so Chinese comes from
// the reader's system. This is deliberate (spec decision 10).
:root {
  --va-font-sans: 'Bender Digits', 'Novecento Wide', 'Microsoft YaHei',
    'PingFang SC', 'Hiragino Sans GB', 'Noto Sans CJK SC', sans-serif;
}
```

- [ ] **Step 5: Rebuild and verify the fonts survived**

```bash
NODE_OPTIONS=--max-old-space-size=4096 pnpm build

echo "--- where did the CSS land? ---"
find dist -name '*.css' | head

echo "--- digits-only face present in built CSS (expect a match) ---"
grep -rl 'U+0030-0039' dist/ || echo "FAIL: unicode-range face was dropped"

echo "--- font files emitted (expect 3) ---"
find dist \( -name '*.otf' -o -name '*.ttf' \) | wc -l

echo "--- background image emitted ---"
find dist -name 'bg.webp'
```

Expected: a match for `U+0030-0039`; **3** font files; `dist/bg.webp` present. Vite can tree-shake unused font assets, which is why this is asserted rather than assumed. Search all of `dist/` rather than `dist/assets/` — the CSS directory name is Vite's choice, not ours, so hardcoding it risks a false failure.

- [ ] **Step 6: Commit**

```bash
git add styles public/fonts public/bg.webp
git commit -m "feat: port the old dark identity onto the Yun theme

Black background, pink primary, Novecento for Latin, Bender for digits via
a unicode-range face, system stack for CJK (bundled fonts have no hanzi)."
```

---

### Task 5: Remove upstream scaffold placeholders

These are user-visible remnants of the Valaxy template that currently misattribute the site to Valaxy's author.

**Files:**
- Modify: `pages/about/index.md`, `locales/zh-CN.yml`
- Delete: `pages/about/site.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Replace the About page**

`pages/about/index.md` currently contains Valaxy's author bio and sponsorship links. Replace the whole file:

```markdown
---
title: 关于我
---

CTF 选手，主要做 misc 和 web，也在做 SRC 漏洞挖掘。

这个站点用来记录 CTF 比赛的 WriteUp、学习笔记，以及 SRC 相关的内容。

- GitHub: [Doc4c3](https://github.com/Doc4c3)
- 哔哩哔哩: [空间](https://space.bilibili.com/498295819)
- E-Mail: 1255893218@qq.com
```

- [ ] **Step 2: Delete the demo page**

```bash
rm pages/about/site.md
```

Plain `rm`, not `git rm` — same reason as Task 1's renames: nothing under `pages/` is tracked yet, so `git rm` fails with `not under version control`. The deletion is captured by `git add` in Step 5.

- [ ] **Step 3: Replace the locale strings**

`locales/zh-CN.yml`:

```yaml
# 你可以像这样自定义 i18n
intro:
  desc: CTFer(misc and web) and SRC researcher
  hi: 你好
```

- [ ] **Step 4: Verify the placeholders are gone**

```bash
NODE_OPTIONS=--max-old-space-size=4096 pnpm build

echo "--- scaffold strings in build output (expect none) ---"
grep -rl 'Valaxy 模版\|Valaxy Theme Yun Preview\|yunyoujun/sponsors' dist/ || echo "OK: placeholders gone"

echo "--- about page built ---"
ls dist/about/index.html
```

Expected: `OK: placeholders gone` and the about page present.

- [ ] **Step 5: Commit**

```bash
git add pages/about locales/zh-CN.yml
git commit -m "content: replace upstream scaffold placeholders with real site pages

The About page carried Valaxy's author bio and sponsor links."
```

---

### Task 6: Migrate the old site's real content

Per spec decision 3: the USB writeup becomes a post, its seven links become the links page, and the `ctf3`–`ctf8` placeholder cards are dropped.

**Files:**
- Create: `pages/posts/usb-keyboard-traffic.md`, `public/images/posts/usb-keyboard-traffic/*.png|jpg` (9 files), `public/files/usb-keyboard-traffic.pdf`, `public/images/avatar.png`
- Modify: `pages/links/index.md`

**Interfaces:**
- Consumes: Task 3's `valaxy.config.ts` (nav already points at `/links`).
- Produces: the final content set; Task 9's live verification checks this post and the PDF.

- [ ] **Step 1: Fetch the USB writeup's assets from the old repo**

Everything for this post exists only in the old repo.

```bash
RAW=https://raw.githubusercontent.com/Doc4c3/DocAceLittleHome.github.io/main
MD="md%E6%BA%90%E6%96%87%E4%BB%B6"   # 目录 md源文件
mkdir -p public/images/posts/usb-keyboard-traffic public/files

# the PDF lives in history/
curl -fsSL -o public/files/usb-keyboard-traffic.pdf \
  "$RAW/history/%E6%B5%81%E9%87%8F%E5%88%86%E6%9E%90%E4%B9%8Busb%E9%94%AE%E7%9B%98%E5%88%86%E6%9E%90.pdf"

# the 8 screenshots live in history/md源文件/, NOT history/
# (all 8 verified 200 on 2026-09-10)
curl -fsSL -o public/images/posts/usb-keyboard-traffic/01.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20123752.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/02.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20124321.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/03.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20130347.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/04.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20130823.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/05.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20131246.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/06.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20131410.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/07.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20132427.png"
curl -fsSL -o public/images/posts/usb-keyboard-traffic/08.png "$RAW/history/$MD/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202025-05-14%20132831.png"

# the WeChat photo is also in history/md源文件/
curl -fsSL -o public/images/posts/usb-keyboard-traffic/09.jpg \
  "$RAW/history/$MD/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20250514131630.jpg"

ls -la public/images/posts/usb-keyboard-traffic public/files
echo "expect 9 images + 1 pdf, all non-zero"
```

Expected: 9 images and the PDF, all non-zero.

- [ ] **Step 2: Write the post**

Create `pages/posts/usb-keyboard-traffic.md`. This is the old repo's
`history/md源文件/流量分析之usb键盘分析.md`, with frontmatter added and every
image reference switched to root-absolute markdown syntax. The conversion
matters: the original uses Windows backslash paths and one **raw HTML** `<img>`,
and the Valaxy docs state raw HTML `<a>` links are not base-adjusted, so the
HTML form must become markdown.

```markdown
---
title: 流量分析之USB键盘分析
date: 2025-05-14
categories:
  - CTF
tags:
  - misc
  - forensics
---

# 流量分析之USB键盘分析

例题：<https://buuoj.cn/challenges#USB>

### 题目分析

刚打开就是一个 rar 和一个 ftm

![打开文件](/images/posts/usb-keyboard-traffic/01.png)

打开 ftm 可以看到一个 key.pcap，用 wireshark 打开 pcap 可以看到这是一个 usb 流量包。

![wireshark](/images/posts/usb-keyboard-traffic/02.png)

再看他的 capture data，是十六位的，可以确定这大概是一个键盘的流量（鼠标是 8 位）

先利用 tshark 将流量中的 capture data 输出为 txt

```shell
.\tshark.exe -r C:\Users\12558\Downloads\key.pcap -T fields -e usb.capdata >"C:\Users\12558\Downloads\usbdata.txt"
```

使用脚本来处理一下

```python
# 使用脚本删除空行
with open('usbdata.txt', 'r', encoding='utf-16') as f:
    lines = f.readlines()
lines = filter(lambda x: x.strip(), lines)
with open('usbdata.txt', 'w', encoding='utf-16') as f:
    f.writelines(lines)

# 将上面的文件用脚本分隔，加上冒号
with open('usbdata.txt', 'r', encoding='utf-16') as f:
    with open('out.txt', 'w', encoding='utf-16') as fi:
        while True:
            a = f.readline().strip()
            if a:
                if len(a) == 16:  # 键盘流量 len 为 16，鼠标为 8
                    out = ''
                    for i in range(0, len(a), 2):
                        if i + 2 != len(a):
                            out += a[i] + a[i + 1] + ":"
                        else:
                            out += a[i] + a[i + 1]
                    fi.write(out)
                    fi.write('\n')
            else:
                break

# 最后用脚本提取
mappings = {
    0x04: "A", 0x05: "B", 0x06: "C", 0x07: "D", 0x08: "E", 0x09: "F", 0x0A: "G", 0x0B: "H", 0x0C: "I", 0x0D: "J", 0x0E: "K", 0x0F: "L",
    0x10: "M", 0x11: "N", 0x12: "O", 0x13: "P", 0x14: "Q", 0x15: "R", 0x16: "S", 0x17: "T", 0x18: "U", 0x19: "V", 0x1A: "W", 0x1B: "X",
    0x1C: "Y", 0x1D: "Z", 0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x2A: "[DEL]", 0x2B: "    ", 0x2C: " ", 0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x32: "~", 0x33: ";",
    0x34: "'", 0x36: ",", 0x37: "."
}

nums = []
with open('out.txt', 'r', encoding='utf-16') as keys:
    for line in keys:
        if line[0] != '0' or line[1] != '0' or line[3] != '0' or line[4] != '0' or line[9] != '0' or line[10] != '0' or \
           line[12] != '0' or line[13] != '0' or line[15] != '0' or line[16] != '0' or line[18] != '0' or line[19] != '0' or \
           line[21] != '0' or line[22] != '0':
            continue
        nums.append(int(line[6:8], 16))

output = ""
for n in nums:
    if n == 0:
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'

print('output :\n' + output)
```

结果如图：

![结果](/images/posts/usb-keyboard-traffic/03.png)

发现他键盘输入的是 KEYXINAN

返回来处理一下 rar 文件，直接打开只看到了一个 16b 的 txt，压缩包有 1.54MB，事情不简单，打开 010 看看

![010](/images/posts/usb-keyboard-traffic/04.png)

原来是文件头的标识处损坏了，把 7A 改成 74 就好了

![修复文件头](/images/posts/usb-keyboard-traffic/05.png)

用 stegsolve 打开

![stegsolve](/images/posts/usb-keyboard-traffic/06.png)

发现在 blue 的 0 通道有一个二维码，扫描结果如下：

![二维码](/images/posts/usb-keyboard-traffic/09.jpg)

结合上文，我们在 usb 的流量分析中得到的 key：xinan。

我们先猜是维吉尼亚加密

![维吉尼亚](/images/posts/usb-keyboard-traffic/07.png)

emmmmm，好像有了？只能说该有的格式都有了，那再试试栅栏吧

![栅栏](/images/posts/usb-keyboard-traffic/08.png)

最后得到了 flag

```
flag{vig3ne2e_is_c00l}
```
```

- [ ] **Step 3: Rewrite the links page**

`pages/links/index.md` — the seven links from the old site's "Some useful links" block, plus the MD5 tool from its CTF grid:

```markdown
---
title: 常用链接
keywords: 链接
description: 常用工具与参考资料
random: false
links:
  - name: 菜鸟编程
    link: https://www.runoob.com/
    avatar: https://www.runoob.com/favicon.ico
    desc: 学点语言
  - name: 云沙箱
    link: https://s.threatbook.com/
    desc: 微步在线云沙箱
  - name: 流程图生成器
    link: https://app.diagrams.net/?src=about
    desc: 有网页版
  - name: 星座定位器
    link: https://bengbuguards.github.io/StarLocator/
    desc: StarLocator
  - name: 一些常见的搜索语法
    link: https://chenoge.github.io/2020/01/02/%E6%90%9C%E7%B4%A2%E8%AF%AD%E6%B3%95/
    desc: Google Hacking 常用语法
  - name: netcat 的使用指南
    link: https://www.bilibili.com/video/BV16t411c7nd/
    desc: 视频教程
  - name: HackTheBox
    link: https://www.hackthebox.eu/
    desc: 练题平台
  - name: faster-MD5
    link: https://github.com/Doc4c3/faster-MD5
    desc: 超大文件 md5 值计算脚本
---

<YunLinks :links="frontmatter.links" :random="frontmatter.random" />
```

The external `netcat` link is the video URL without the old site's tracking query string. The old site's `ctf3`–`ctf8` cards are intentionally dropped — they pointed at files that never existed.

- [ ] **Step 4: Add an avatar**

```bash
mkdir -p public/images
curl -fsSL -o public/images/avatar.png "https://avatars.githubusercontent.com/u/$(curl -fsSL https://api.github.com/users/Doc4c3 | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')?s=400"
ls -la public/images/avatar.png
```

Expected: a non-zero PNG. If the GitHub avatar is unavailable, any square image will do — this is the only asset the plan does not source from the old repo or local disk.

- [ ] **Step 5: Rebuild and verify**

```bash
NODE_OPTIONS=--max-old-space-size=4096 pnpm build

echo "--- USB post built ---"
ls dist/posts/usb-keyboard-traffic/index.html

echo "--- its images emitted (expect 9) ---"
find dist/images/posts/usb-keyboard-traffic -type f | wc -l

echo "--- PDF emitted ---"
ls dist/files/usb-keyboard-traffic.pdf

echo "--- links page built ---"
ls dist/links/index.html

echo "--- all post pages (expect 10) ---"
find dist/posts -name 'index.html' | wc -l
```

Expected: all present; **9** images; **10** posts (9 renamed + USB).

- [ ] **Step 6: Commit**

```bash
git add pages/posts/usb-keyboard-traffic.md pages/links public/images public/files
git commit -m "content: migrate USB writeup, links page, PDF and avatar

The USB writeup used Windows backslash paths and a raw HTML <img>, which
Valaxy does not base-adjust; converted to markdown image syntax."
```

---

### Task 7: Fix the GitHub Pages workflow

**Files:**
- Modify: `.github/workflows/gh-pages.yml`

**Interfaces:**
- Consumes: `package.json` scripts from the scaffold (`build` → `valaxy build --ssg`).
- Produces: the CI contract Task 9 relies on — build from `main`, publish `dist/` to `gh-pages`.

- [ ] **Step 1: Rewrite the workflow**

The scaffold's version runs `npm i` against a `pnpm-lock.yaml` and pins `actions/checkout@v2` / `actions/setup-node@v2`.

```yaml
name: GitHub Pages

on:
  push:
    branches:
      # The branch where the project source code resides
      - main
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4

      - name: Use Node.js
        uses: actions/setup-node@v4
        with:
          node-version: lts/*
          cache: pnpm

      - name: 📦 Install Dependencies
        run: pnpm install --frozen-lockfile

      - name: 🌌 Build Valaxy Blog
        run: pnpm build
        env:
          NODE_OPTIONS: --max-old-space-size=4096

      - name: 🪤 Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v4
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./dist
          force_orphan: true
```

Keeping `force_orphan: true` matches the scaffold and keeps the generated branch from accumulating history. `pnpm/action-setup@v4` reads the pinned version from `packageManager` if present, otherwise installs current stable; the local toolchain is pnpm 10.33.0.

- [ ] **Step 2: Verify the YAML parses and the key fields are right**

```bash
python -c "
import yaml, sys
w = yaml.safe_load(open('.github/workflows/gh-pages.yml', encoding='utf-8'))
assert 'main' in w[True]['push']['branches'], 'main must be a trigger branch'
steps = w['jobs']['build']['steps']
assert any('pnpm install' in str(s.get('run','')) for s in steps), 'must use pnpm'
assert any(s.get('with',{}).get('publish_dir') == './dist' for s in steps), 'publish_dir must be ./dist'
print('workflow OK')
"
```

Expected: `workflow OK`.

If `yaml` is missing: `uv run --with pyyaml python -c "..."` with the same body.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/gh-pages.yml
git commit -m "ci: use pnpm, current actions, and node lts for the Pages build"
```

---

### Task 8: Preserve the old site and seed `gh-pages`

**⚠️ Steps 4 and 5 push to GitHub. Do not run them until the user has explicitly confirmed.** Steps 1–3 are local only.

Pushing source to `main` takes the live site down, because Pages currently serves `main`'s root and Valaxy's root has no `index.html`. This task puts the *current* old site on `gh-pages` first, so switching Pages to it changes nothing visually.

**Files:**
- No file changes. Git operations only.

**Interfaces:**
- Consumes: nothing.
- Produces: an `origin/gh-pages` branch containing the old site, and a `legacy-v1` tag. Task 9 depends on both.

- [ ] **Step 1: Add the remote (local)**

```bash
git remote add origin https://github.com/Doc4c3/DocAceLittleHome.github.io.git
git remote -v
```

Expected: `origin` for both fetch and push.

- [ ] **Step 2: Fetch the old site and tag it (local)**

```bash
git fetch origin main
git tag legacy-v1 origin/main
git log --oneline -1 legacy-v1
```

Expected: the tag points at the old site's last commit (`60add233` as observed on 2026-09-10).

- [ ] **Step 3: Create `gh-pages` from the old site (local)**

```bash
git branch gh-pages origin/main
git log --oneline -1 gh-pages
git show --stat --oneline gh-pages | head -20
```

Expected: `gh-pages` points at the same commit as `legacy-v1` and contains `index.html`, `font/`, `history/`.

- [ ] **Step 4: ⚠️ Push the tag and `gh-pages` — requires user confirmation**

```bash
git push origin legacy-v1
git push origin gh-pages
```

Expected: both succeed. If `gh-pages` is rejected because it already exists remotely, stop and inspect — the plan assumes it does not exist.

- [ ] **Step 5: ⚠️ USER ACTION — hand these two settings to the user**

Print these instructions to the user; do not attempt them programmatically.

1. **Settings → Pages → Source → `gh-pages` / root.** The site should still look identical, since `gh-pages` now holds a copy of the old site.
2. **Settings → Actions → General → Workflow permissions → Read and write.** Without this the workflow's push to `gh-pages` is rejected in Task 9.

- [ ] **Step 6: Verify the switch changed nothing**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://doc4c3.github.io/DocAceLittleHome.github.io/
curl -s -o /dev/null -w "%{http_code}\n" https://doc4c3.github.io/DocAceLittleHome.github.io/history/ctf1-preview.png
```

Expected: `200` and `200`. Still the old site — that is the point of this ordering.

---

### Task 9: Switch over and verify live

**⚠️ Pushes to GitHub. Requires explicit user confirmation.**

**Files:**
- No file changes except possibly the `packageManager` field noted in step 1.

**Interfaces:**
- Consumes: everything above.
- Produces: the live site.

- [ ] **Step 1: Confirm prerequisites before pushing**

```bash
echo "--- local build is green ---"
NODE_OPTIONS=--max-old-space-size=4096 pnpm build >/dev/null && echo "build OK"
echo "--- gh-pages exists locally ---"
git rev-parse --verify gh-pages
echo "--- remote knows gh-pages ---"
git ls-remote --heads origin gh-pages
```

Expected: `build OK`, a SHA, and a `gh-pages` ref from the remote. If the remote ref is missing, Task 8 step 4 did not run.

- [ ] **Step 2: ⚠️ Force-push source onto `main`**

Local history is unrelated to `origin/main`'s, so this requires a force push. This is only safe because Task 8 preserved the old site on `gh-pages` and tagged it `legacy-v1`.

```bash
git push --force-with-lease origin main
```

Prefer `--force-with-lease` over `--force`: it aborts if the remote moved since the last fetch, which is exactly the guard wanted when overwriting a branch.

- [ ] **Step 3: Watch the workflow**

```bash
gh run list --limit 5
```

If `gh` is unavailable, check the Actions tab in the browser. Expected: a run triggered by the push to `main`, completing green, publishing `dist/` to `gh-pages`.

- [ ] **Step 4: Verify the live site**

```bash
BASE=https://doc4c3.github.io/DocAceLittleHome.github.io

echo "--- home page ---"
curl -s -o /dev/null -w "  %{http_code}  home\n"                     "$BASE/"
echo "--- a post page ---"
curl -s -o /dev/null -w "  %{http_code}  post\n"                     "$BASE/posts/wanqubei-2026/"
echo "--- a migrated image ---"
curl -s -o /dev/null -w "  %{http_code}  image\n"                    "$BASE/images/posts/pengcheng-2025/01.png"
echo "--- the USB PDF ---"
curl -s -o /dev/null -w "  %{http_code}  pdf\n"                      "$BASE/files/usb-keyboard-traffic.pdf"
echo "--- a font ---"
curl -s -o /dev/null -w "  %{http_code}  font\n"                     "$BASE/fonts/Bender.otf"
echo "--- background ---"
curl -s -o /dev/null -w "  %{http_code}  bg\n"                       "$BASE/bg.webp"
echo "--- the assets prefix really is served from the subpath ---"
curl -s "$BASE/" | grep -o '/DocAceLittleHome.github.io/assets/[^"]*' | head -2
```

Expected: `200` for all six, and asset URLs containing the subpath prefix. A `404` on assets while `/` returns `200` means `vite.base` did not take effect.

- [ ] **Step 5: Report the outstanding user action**

If any check in step 4 fails with `404` across the board, the most likely cause is that the Pages source is still `main` rather than `gh-pages`. Re-check the Task 8 step 5 settings before debugging anything else.

---

## Self-Review

**Spec coverage**

| Spec requirement | Task |
|---|---|
| §1 identity table (url, title, subtitle, description, timezone, mode, author, social) | 3 |
| §1 `vite.base` | 3 |
| §1 placeholder cleanup (about, site.md, locales) | 5 |
| §2 ASCII slugs, all 9 | 1 |
| §2 frontmatter + three-category scheme | 1 |
| §2 frozen dates | 1 |
| §2 old content: USB post, links page, MD5 link, drop ctf3–8 | 6 |
| §2 raw HTML `<img>` → markdown | 6 |
| §3 62 → 61 images migrated, ASCII renumbering | 2 |
| §3 one unrecoverable image | 2 step 3 |
| §3 fonts, background, WebP | 4 |
| §3 typography: digits-only `unicode-range`, one Novecento family, CJK stack | 4 |
| §3 theme wiring: colours, bg_image, banner, nav retarget | 3, 4 |
| §3 splash dropped | 4 (simply not implemented) |
| §4 order of operations: seed gh-pages first | 8 |
| §4 workflow fixes | 7 |
| §4 two manual GitHub settings | 8 step 5 |
| §4 assets that exist only in the old repo | 4 step 1, 6 step 1 |
| Verification steps 1–6 in the spec | 3 step 3-4, 4 step 5, 6 step 5, 9 step 4 |

No gaps found.

**Placeholder scan.** No `TBD`, `TODO`, "implement later", or "similar to Task N". Every code and YAML block is complete and pasteable. The one deliberate unknown — the WebP conversion tool available on the machine — is handled with three concrete ordered alternatives plus a documented fallback, rather than a placeholder.

**Type and name consistency.** Cross-checked: the ten frozen slugs appear identically in Global Constraints, Task 1, Task 6 and Task 9. `public/images/posts/usb-keyboard-traffic/` uses the same slug as `pages/posts/usb-keyboard-traffic.md`. `bg.webp` is referenced by `valaxy.config.ts` in Task 3 and created in Task 4 — the ordering note in Task 3 step 2 covers the gap. `Bender Digits` / `Novecento Wide` family names match between the `@font-face` declarations and the `--va-font-sans` stack. `/links` matches between the Task 3 nav entry and Task 6's page path.
