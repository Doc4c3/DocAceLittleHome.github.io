import type { UserThemeConfig } from 'valaxy-theme-yun'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineValaxyConfig } from 'valaxy'

// add icons what you will need
const safelist = [
  'i-ri-home-line',
]

// Mirrors `vite.base` below and `siteConfig.url`. GitHub serves this repo as a
// *project* site, so the deploy origin is the account root and the site itself
// lives under the repo subpath.
const DEPLOY_ORIGIN = 'https://doc4c3.github.io'
const DEPLOY_BASE = '/DocAceLittleHome.github.io'

/**
 * `vite-ssg-sitemap` builds every entry as `new URL(route, hostname)`, which
 * discards the hostname's own path — so all the `<loc>` values lose the project
 * subpath and point at the account root, which 404s. The feeds are unaffected
 * because they concatenate strings out of the same `url` field, and that
 * asymmetry is what hid this. Re-add the subpath, and drop `/404`, which should
 * not be indexed.
 */
async function fixSitemapLocPaths() {
  const sitemap = resolve('dist/sitemap.xml')
  const ready = () =>
    existsSync(sitemap) && readFileSync(sitemap, 'utf-8').includes('<loc>')

  // Valaxy does not await the sitemap's own write — vite-ssg-sitemap writes it
  // from a floating `streamToPromise(...).then()` — so give it a bounded moment.
  const deadline = Date.now() + 5000
  while (!ready() && Date.now() < deadline)
    await new Promise(done => setTimeout(done, 50))

  if (!ready()) {
    console.warn('[sitemap] dist/sitemap.xml was not written; <loc> paths left as-is')
    return
  }

  let rewritten = 0
  let dropped = 0
  const fixed = readFileSync(sitemap, 'utf-8').replace(/<url>[\s\S]*?<\/url>/g, (entry) => {
    const loc = entry.match(/<loc>([^<]*)<\/loc>/)?.[1]
    if (!loc)
      return entry
    if (loc === `${DEPLOY_ORIGIN}/404`) {
      dropped += 1
      return ''
    }
    // Already-prefixed entries are left alone, so a re-run cannot double-prefix.
    if (!loc.startsWith(`${DEPLOY_ORIGIN}/`) || loc.startsWith(`${DEPLOY_ORIGIN}${DEPLOY_BASE}`))
      return entry
    rewritten += 1
    return entry.replace(loc, `${DEPLOY_ORIGIN}${DEPLOY_BASE}${loc.slice(DEPLOY_ORIGIN.length)}`)
  })

  writeFileSync(sitemap, fixed)
  console.log(`[sitemap] added the project subpath to ${rewritten} <loc> paths, dropped ${dropped}`)
}

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
    // `ssgOptions` is a top-level Vite config key, not part of Valaxy's own
    // `build` section: valaxy/dist/node/index.d.mts:1035 augments Vite's
    // `UserConfig` with it and valaxy/dist/shared/valaxy.Cb_HdczD.mjs:6294
    // reads it as `viteConfig.ssgOptions`. Putting it under `build` would be
    // silently ignored.
    ssgOptions: {
      onFinished: fixSitemapLocPaths,
    },
  },

  theme: 'yun',

  themeConfig: {
    type: 'nimbo',

    // The `dark` class is applied at runtime by useValaxyDark ->
    // useDark(themeConfig.valaxyDarkOptions.useDarkOptions). Left unset, VueUse's
    // `initialValue: 'auto'` (i.e. `prefers-color-scheme`) decides, and every
    // ported colour lives under `html.dark` (styles/css-vars.scss) — so a reader
    // whose OS is in light mode was getting the theme's white `:root` instead.
    // Start dark regardless, while leaving the nav toggle functional.
    valaxyDarkOptions: {
      circleTransition: true,
      useDarkOptions: { initialValue: 'dark' },
    },

    banner: {
      enable: true,
      title: "DA's BLOG",
    },

    colors: {
      primary: '#FFC0CB',
    },

    bg_image: {
      enable: true,
      url: '/DocAceLittleHome.github.io/bg.webp',
      dark: '/DocAceLittleHome.github.io/bg.webp',
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

    footer: {
      // The theme defaults to a "Sponsor YunYouJun" donation link in the
      // footer icon. It is upstream branding, not this blog's.
      icon: {
        enable: false,
      },
      since: 2025,
    },
  },

  unocss: { safelist },
})
