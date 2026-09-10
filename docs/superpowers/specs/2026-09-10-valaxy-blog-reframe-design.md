# Blog Reframe onto Valaxy — Design

**Date:** 2026-09-10
**Status:** Approved — spec reviewed and confirmed 2026-09-10
**Project root:** `C:\Users\12558\Desktop\知识库\DocAceLittleHome`

## Goal

Replace the hand-written static site currently live at
`https://doc4c3.github.io/DocAceLittleHome.github.io/` with the Valaxy site
scaffolded at the project root, keeping the same URL, and porting the old
site's dark visual identity onto the new framework.

## Decisions

| # | Decision | Chosen |
|---|---|---|
| 1 | Where the new site goes live | Replace in place, same URL |
| 2 | Visual direction | Port the old dark look onto Yun |
| 3 | Old landing-page content | Migrate what is real, drop the stubs |
| 4 | Dates for undated posts | Infer from in-post image timestamps |
| 5 | Post filenames / URL slugs | Rename all posts to ASCII slugs |
| 6 | Old welcome splash | Dropped |
| 7 | Deployment mechanism | `main` = source, `gh-pages` = site, seeded before source lands |
| 8 | Category scheme | Exactly three site-wide: `CTF`, `SRC`, `Learning` |
| 9 | Learning-material migration | Deferred to a follow-up session (see Out of scope) |
| 10 | Chinese (CJK) font | System stack — zero download cost, appearance varies by reader OS |

## Current state

### Old site (live)

- Repo `Doc4c3/DocAceLittleHome.github.io`, **single branch `main`**, no `gh-pages`.
- The repo name does not match the account name, so GitHub serves it as a
  **project site** under a subpath. `https://doc4c3.github.io/` itself is 404.
- Pages currently serves the **`main` root**. Verified live: `index.html` and
  `history/ctf1-preview.png` return 200.
- Content is one hand-written `index.html`: black background, Novecento Wide +
  Bender fonts, "DA's BLOG", a welcome splash, a links list, and a paginated
  "recorded CTFs" grid whose `ctf3`–`ctf8` entries point at files that do not
  exist.
- The HTML requests `font/NovecentoWide-Regular.otf`, which is **not** in the
  repo (404 live). The fonts actually present are named differently — see below.

### New site (local)

- Valaxy `1.0.0-rc.9` + `valaxy-theme-yun` `1.0.0-rc.9`, installed, `node_modules`
  present.
- **Not a git repository.**
- Scaffold is still upstream-default and user-visible as such: `site.config.ts`
  title `Valaxy Theme Yun`, description `Valaxy Theme Yun Preview.`, `url`
  pointing at the GitHub *repo* page; `pages/about/index.md` containing the
  Valaxy author's bio and sponsor links; `locales/zh-CN.yml` saying `Valaxy 模版`.
- `styles/index.scss` and `styles/css-vars.scss` are empty (comments only).
- 9 posts in `pages/posts/`. Only `[湾区杯2026]记录一下.md` has frontmatter, and
  it uses ctf-swarm fields (`ctf`, `difficulty`, `points`, `flag_format`) that
  Valaxy ignores. The other 8 have none.
- 62 image references across 7 posts, **all absolute local Windows paths**.
  Verified: 61 resolve on local disk; 1 (`xwechat_files\...\87fa1e...jpg`) does not.
- `.valaxy/route-map.d.ts` is a stale generated cache (written 13:43:55; most
  posts were copied in at 13:49–13:50). It registers only one post route.

### Confirmed defects

1. **Bracket filename breaks routing.** `pages/posts/[湾区杯2026]记录一下.md`
   generates the route
   `/posts/:湾区杯2026%E8%AE%B0%E5%BD%95%E4%B8%80%E4%B8%8B` — `[湾区杯2026]` is
   parsed as a Vue Router dynamic parameter, so that URL is a route template
   requiring an argument, not a page. Deterministic, not a stale-cache artifact.
2. **No base path.** `valaxy.config.ts` sets no `vite.base`. For a project site
   this means every asset 404s after deploy.
3. **Wrong `siteConfig.url`.** Points at the repo page rather than the Pages URL;
   `url` drives canonical links and RSS.
4. **Workflow is misconfigured.** `.github/workflows/gh-pages.yml` runs `npm i`
   against a `pnpm-lock.yaml`, and pins `actions/checkout@v2` /
   `actions/setup-node@v2`.
5. **Pushing source to `main` takes the live site down.** Valaxy's project root
   contains no `index.html` (it is generated at build time). Pages serves `main`'s
   root today, so once source lands there the URL 404s until Pages is repointed
   *and* `gh-pages` is populated.
6. **The build does not currently succeed.** `pnpm build` fails with
   `[PARSE_ERROR] '0'-prefixed octal literals and octal escape sequences are
   deprecated`, one error per Windows-backslash image path. Markdown image paths
   are compiled into JS `import` statements, so `\1`, `\U` etc. inside
   `C:\Users\...` are read as JavaScript escape sequences and the generated module
   is syntactically invalid. All **62 refs across 7 posts** are affected. `dist/`
   ends up with only `feed.xml` and no `index.html`.
   A second error follows in the `build:after` hook —
   `TypeError: Cannot read properties of undefined (reading 'replace')` inside
   `xml-js`'s `writeCdata`, reached from `feed` generating the RSS feed. This may
   be a cascade from the failed build; it should be re-checked once the parse
   errors are gone.

   Consequence for planning: the build cannot be used as a per-task check until
   both the image paths and the missing frontmatter are fixed. There is no unit
   test framework in this project, so task verification is by build, built-artifact
   assertions, and live HTTP checks.

## Design

### 1. Identity and base path

`site.config.ts`:

| Field | Now | Becomes |
|---|---|---|
| `url` | `https://github.com/Doc4c3/DocAceLittleHome.github.io` | `https://doc4c3.github.io/DocAceLittleHome.github.io/` |
| `title` | `Valaxy Theme Yun` | `DA's BLOG` |
| `subtitle` | *(unset)* | `mostly about CTFs and hacking` |
| `description` | `Valaxy Theme Yun Preview.` | `CTFer(misc and web) and SRC researcher` |
| `timezone` | *(unset)* | `Asia/Hong_Kong` |
| `mode` | *(unset → auto)* | `dark` |
| `author.name` | `DocAcer` | unchanged |
| `author.avatar` | *(unset)* | `/images/avatar.png` — new file added to `public/` |
| `author.email` | *(unset)* | `1255893218@qq.com` |
| `author.link` | *(unset)* | `https://github.com/Doc4c3` |
| `social` | RSS / GitHub / Bilibili / E-Mail | kept, but **two entries fixed** — see below |

**Two social entries needed correcting.** An earlier revision of this spec
claimed the scaffold's `social` block was "already correct". That was wrong, and
a task review caught it. The theme emits social links **verbatim, with no base
handling** — unlike markdown links, which are base-adjusted automatically:

- `RSS` was `link: '/atom.xml'`. Emitted as a root-absolute `href="/atom.xml"`,
  which on a project-site subpath resolves to
  `https://doc4c3.github.io/atom.xml` — outside the site — while the real feed
  is at `.../DocAceLittleHome.github.io/atom.xml`. Becomes
  `/DocAceLittleHome.github.io/atom.xml`.
- `E-Mail` was `link: '1255893218@qq.com'`. Emitted as
  `href="1255893218@qq.com"`, which a browser resolves relative to the current
  directory and 404s. Becomes `mailto:1255893218@qq.com`.

Both were verified against the built output, not inferred. Any future root-relative
value placed in `themeConfig` or `siteConfig.social` needs the same treatment —
`withBase()` does not apply there.

`valaxy.config.ts` gains:

```ts
vite: { base: '/DocAceLittleHome.github.io/' },
```

Confirmed against the official docs and against
`node_modules/valaxy/dist/node/index.d.mts:847` (`vite?: UserConfig` is a valid
top-level key). The docs state: *"Repositories named `your-username.github.io`
are served from `/` and do not need a custom base. Other repository names are
supported as project sites; configure `base: '/repository-name/'`."*

`url` and `base` are different fields and both are required: `url` is the
canonical/permalink URL used by SSG and RSS; `base` is the asset prefix. Setting
only one produces a site that loads with dead links.

Also: `banner.title` set, and the nav entry currently pointing at `decimo.top`
retargeted to `/links`.

**Placeholder cleanup:** rewrite `pages/about/index.md` as the real bio; delete
`pages/about/site.md`; replace `locales/zh-CN.yml` contents; and **override
`themeConfig.footer`** to drop the theme's default `Sponsor YunYouJun` donation
link, which renders on every page.

Three corrections to this section, each measured after the fact rather than
assumed:

- **The footer sponsor link was missed in the original scope.** The theme's
  default footer (`node_modules/valaxy-theme-yun/node/config.ts:60-70`) emits
  `href="https://www.yunyoujun.cn/sponsors/"` on all 23 pages unless overridden.
  It is upstream branding of the same class as the About-page bio and was found
  during execution, not design.
- **`locales/zh-CN.yml`'s `intro.*` keys are not referenced anywhere** in Valaxy,
  `valaxy-theme-yun`, or `pages/`. Rewriting the file is therefore source
  hygiene, **not** a rendered change — an earlier claim that these strings were
  user-visible was wrong. The homepage description has its own owner:
  `site.config.ts`'s `description`.
- **`locales/en.yml` was left untouched** and still reads `Valaxy Template` /
  `Hello, Valaxy!` on the same dead keys. Same class of leftover; no rendered
  effect. Deferred, not forgotten.

### 2. Content model

**Filenames.** All 9 posts renamed to ASCII slugs. `title` lives in frontmatter
and is what appears on the page, so nothing user-visible is lost. This removes
the bracket routing defect and the percent-encoded URLs together.

**Frontmatter.** Every post gains `title`, `date`, `categories`, `tags`.

**Categories — exactly three, site-wide:** `CTF`, `SRC`, `Learning`. This is a
deliberate change from the per-competition scheme considered earlier: competition
names were too fine-grained, and the blog needs to accommodate learning material
that is not CTF at all.

`tags` carry what categories no longer do: the competition name (`湾区杯2026`,
`鹏城杯2025`, …) plus discipline tags (`web`, `pwn`, `reverse`, `crypto`,
`forensics`, `misc`, `ai`). Discipline tags are assigned per post from that
post's own section headings. The ctf-swarm-only fields in the `湾区杯2026` post
are normalised away.

**Post map** — slug, date, competition tag. Dates were inferred from in-post
screenshot timestamps and then **confirmed by the author on 2026-09-10**. All
nine get `categories: [CTF]`:

| Post | Slug | Date | Competition tag | Date source |
|---|---|---|---|---|
| 第十届上海市大学生网络安全大赛WriteUp | `shanghai-2025` | 2025-08-06 | 上海市赛 | screenshots |
| 湾区杯 | `wanqubei-2025` | 2025-09-08 | 湾区杯 | Typora stamps |
| 第五届长城杯 | `greatwall-5` | 2025-09-14 | 长城杯 | screenshots |
| ycb2025wp (羊城杯2025) | `ycb-2025` | 2025-10-11 | 羊城杯2025 | Typora stamps |
| 2025高校网络安全管理运维赛 | `gaoxiao-2025` | 2025-10-20 | 高校赛 | screenshots; author-confirmed |
| 鹏城杯2025 | `pengcheng-2025` | 2025-12-13 | 鹏城杯2025 | Typora stamps |
| PWN的学习日志-基础术语 | `pwn-basics` | 2026-01-27 | — (learning note) | H1 reads `（2026/1/27）` |
| 盘古石-DA | `pangushi-da` | 2026-05-10 | 盘古石 | screenshots; author-confirmed |
| [湾区杯2026]记录一下 | `wanqubei-2026` | 2026-09-04 | 湾区杯2026 | existing frontmatter |

Plus one new post: the migrated USB writeup (`usb-keyboard-traffic`).

**Category occupancy today is 10 / 0 / 0.** SRC and Learning are created empty
and stay empty until the pending learning material is migrated (see Out of
scope). That is intentional — the scheme exists so those notes have a home
without a later restructure.

Slugs and dates are frozen: they appear in published URLs and RSS, so changing
either after launch breaks links.

**Old content, per decision 3:** the USB writeup becomes a post; its 7 "useful
links" become the `/links` page; the MD5 tool becomes a link to
`github.com/Doc4c3/faster-MD5`. The `ctf3`–`ctf8` placeholder cards are dropped.

The USB writeup source (`history/md源文件/流量分析之usb键盘分析.md`) contains a
raw HTML `<img src="history\...">`. The Valaxy docs state raw HTML `<a>` links are
*not* base-adjusted, so this must be converted to markdown image syntax.

### 3. Assets and the dark look

**Images.** 62 refs → `public/images/posts/<slug>/01.png, 02.png, …`, renumbered
in document order. Sequential ASCII names remove both the Chinese-with-spaces
names and the meaningless Typora names; per-post folders make collisions
impossible. Refs become root-absolute `/images/posts/<slug>/NN.png`, which the
docs confirm is base-adjusted automatically *for markdown images*.

**61 of 62 are present on local disk. One is unrecoverable.** Correcting an
earlier error in this spec: the missing file is
`87fa1e7675cf88f9b93434fff86853c0.jpg` in the **上海市赛** post
(`第十届上海市大学生网络安全大赛WriteUp.md:98`), inside the `easy_misc` section
— a WeChat temp file for a QR-code screenshot, deleted from
`xwechat_files\...\temp\RWTemp\`. It is **not** the old repo's
`history/md源文件/微信图片_20250514131630.jpg`; that image belongs to the USB
writeup, which is a different post and a different competition. The two were
conflated in an earlier revision.

Handling: replace that one reference with a visible placeholder line rather than
shipping a broken `<img>`. Author may re-supply the file.

**Fonts and background**, sourced from the old repo via raw GitHub URLs:

- `font/Bender.otf`, `font/Novecento-Wide-Bold-2.otf`,
  `font/Novecento-wide-Normal-2.ttf` → `public/fonts/`. Typography scheme below.
- `8f8a8af6d4afbc463b4b43460df474493d0c6123.png` (**5.45 MB**) → converted to
  WebP before shipping. This is the largest asset on the site by an order of
  magnitude.
- Also fetched from the old repo, for the migrated USB writeup:
  `history/流量分析之usb键盘分析.pdf`, its 8 screenshots, and
  `history/md源文件/微信图片_20250514131630.jpg`. None of these exist on local
  disk — they live only in the old repo.

#### Typography

Glyph coverage was measured directly from the font tables, not assumed:

| Font | digits 0-9 | A-Z / a-z | CJK hanzi |
|---|---|---|---|
| `Bender.otf` | 10/10 | 26/26 | **0** |
| `Novecento-Wide-Bold-2.otf` | 10/10 | 26/26 | **0** |
| `Novecento-wide-Normal-2.ttf` | 10/10 | 26/26 | **0** |

Two consequences drive the implementation:

1. **Bender for digits requires `unicode-range`, not font stack order.** All
   three fonts contain digits, and CSS fallback is first-match-wins per glyph, so
   putting `'Bender'` after `'Novecento Wide'` would leave digits in Novecento.
   Declaring a digits-only face and placing it *first* is what makes it work:

   ```css
   @font-face {
     font-family: 'Bender Digits';
     src: url('/fonts/Bender.otf') format('opentype');
     unicode-range: U+0030-0039;   /* 0-9 only */
   }
   /* digits resolve to Bender; every other glyph falls through */
   --va-font-sans: 'Bender Digits', 'Novecento Wide', 'Microsoft YaHei',
                   'PingFang SC', 'Hiragino Sans GB', 'Noto Sans CJK SC', sans-serif;
   ```

2. **Novecento cannot render Chinese** — zero hanzi, zero CJK punctuation. All
   CJK goes through the system stack named above. Accepted trade-off (decision
   10): zero download cost, but Chinese appearance varies by reader OS and none
   of those faces match Novecento's condensed wide style.

`@font-face` must assign our own family name and weight per file. The two
Novecento files declare **different embedded family names** — `"Novecento wide"`
(bold) and `"Novecento wide Normal"` (regular) — so relying on the embedded names
would yield a regular-weight bold. Declare both under one family name
(`'Novecento Wide'`) with explicit `font-weight: 400` and `700`.

**Theme wiring.** The Yun theme already exposes the needed knobs:

| Old site | Yun knob | Value |
|---|---|---|
| black background | `styles/css-vars.scss` → `--va-c-bg` (+ `--va-c-bg-soft`, `--va-c-bg-light`) | `#000`; theme default is `#1a1a1d` |
| pink hover | `themeConfig.colors.primary` | `#FFC0CB`; default `#0078E7` |
| typography | `--va-font-sans` / `--va-font-mono` | stack as given above; mono stays available for code blocks |
| background image | `themeConfig.bg_image` | `{ enable: true, url: '/bg.webp', dark: '/bg.webp', opacity: 0.15 }` — opacity is a judgement call, tune on first render |
| "DA's BLOG" wordmark | `banner.title` + `--yun-home-hero-name-color` | title as-is; colour `#fff` |

`themeConfig.type` stays at its default `'nimbo'` — the two variants differ in
layout structure, and the old site carries no structural information to choose
between them.

The pink comes from the old site's `:hover { background-color: pink }` on links
and pagination. Applied as `colors.primary` it reaches the nav, links, and tags
at once rather than needing per-element overrides.

**Splash dropped** (decision 6). The theme's `prologue` option is commented out
in `node_modules/valaxy-theme-yun/types/index.d.ts:143-149`, so it is not
available as a config toggle in rc.9; porting the splash would require a custom
component plus layout override.

### 4. Deployment

**Order of operations** (decision 7) — chosen so the live URL never 404s:

1. `git init` locally; add the remote.
2. Fetch `origin/main`; create `gh-pages` from the current `main` content and
   push it. The old site now exists on two branches.
3. **User:** Settings → Pages → Source → `gh-pages`. The URL still shows the old
   site — nothing visibly changes.
4. Push Valaxy source to `main`. Because the local history is unrelated to
   `origin/main`'s, this requires a force push. This is safe **only because step
   2 preserved the old site**; also tag the old `main` (e.g. `legacy-v1`) as a
   second recovery path.
5. The workflow builds and replaces `gh-pages` with the new site. Site goes live.

**Workflow fixes** to `.github/workflows/gh-pages.yml`: pnpm with
`--frozen-lockfile` instead of `npm i`; bump `actions/checkout` and
`actions/setup-node` to current versions; keep `publish_dir: ./dist` and
`force_orphan: true`. `on.push.branches` already includes `main` — correct as-is.

**Two manual GitHub settings, both owned by the user:**

1. Settings → Actions → General → Workflow permissions → *Read and write*
   (without this the push to `gh-pages` is rejected).
2. Settings → Pages → Source → `gh-pages`.

**Nothing is pushed to GitHub without explicit confirmation**, since that reaches
beyond the local machine.

## Verification

In order:

1. `pnpm build` succeeds locally.
2. Built `dist/index.html` references `/DocAceLittleHome.github.io/assets/…` —
   proves `vite.base` took effect.
3. No post route in the built output contains `:` — proves the bracket defect is
   gone.
4. All post image paths resolve inside `dist/`.
5. The built CSS contains a `@font-face` with `unicode-range: U+0030-0039`, and
   all three font files are present in `dist/` — proves the digits-only face
   survived the build rather than being tree-shaken.
6. After deploy, fetch the live URL and confirm 200 for: the home page, one post
   page, one migrated image, and the USB PDF.

## Out of scope

- **Learning-material migration.** ~17 notes outside the blog are deliberately
  deferred to a follow-up session. Inventory, so the deferral is concrete:
  - `src/` — `SRC学习蓝图.md`, `阶段0-规则与评级/03-阿里ASRC评级规则.md`,
    `阶段0/05-合规红线与法律.md`, `阶段1-Web漏洞/01…05` (SQL注入 ×3, 命令注入,
    PHP弱类型) + `README.md`, `SQL.md` → category `SRC`
  - `web/` — 爬虫学习一, SOCKET编程学习一/二 → `Learning`
  - `pwn/` — PWN的学习日志-小提示 → `CTF`
  - `re/` — Windows绕过安全 → `Learning`
  - `ai_learning/` — AI学习中。。。🫠 → `Learning`
  - `ftp/` — FTP 命令速查小指南 → `Learning`
  - `车/` (5,924 files) is a SavvyCAN tool dump, not content. Excluded permanently.
- Search. `siteConfig.search.enable` stays `false`.
- Comments, analytics, RSS beyond what `siteConfig.url` already enables.
- `Dockerfile`, `nginx.conf`, `netlify.toml`, `vercel.json` — left as scaffold
  defaults; they are unused by the GitHub Pages deploy.
- Any visual redesign beyond porting the existing dark identity.

## Risks

| Risk | Mitigation |
|---|---|
| Force push to `main` destroys the old site | Old site preserved on `gh-pages` (step 2) and a `legacy-v1` tag before the force push |
| Post renamed but a cross-post link left stale | Post URLs are new; the old site had no inbound deep links to preserve |
| 5.45 MB background left uncompressed | Converted to WebP; verified by checking the emitted file size |
| WebP conversion tooling unavailable locally | Check before committing to it; fall back to a resized PNG and record the size |
| Chinese renders differently per reader OS | Accepted trade-off of decision 10. If it looks wrong on other devices, revisit by bundling a subsetted CJK font — the stack is a one-line change |
| Digits-only `unicode-range` face ignored or tree-shaken | Verification step 5 asserts the face and all three font files survive into `dist/` |
