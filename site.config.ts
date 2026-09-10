import { defineSiteConfig } from 'valaxy'

export default defineSiteConfig({
  url: 'https://doc4c3.github.io/DocAceLittleHome.github.io/',
  lang: 'zh-CN',
  title: "DA's BLOG",
  subtitle: 'mostly about CTFs and hacking',
  description: 'CTFer(misc and web) and SRC researcher',
  timezone: 'Asia/Hong_Kong',
  // Valaxy reads `mode` in exactly one place — valaxy/dist/shared/valaxy.Cb_HdczD.mjs:650,
  // `if (config.siteConfig.mode === "auto")` — and has no branch for 'dark'. Setting
  // 'dark' is therefore inert AND suppresses the two things that branch emits: the
  // inline critical CSS (`html.dark { --va-c-bg: #000 }`) and the pre-hydration
  // localStorage script. Dark is forced by
  // `themeConfig.valaxyDarkOptions.useDarkOptions.initialValue` instead; 'auto' here
  // only asks for those pre-hydration head fragments.
  mode: 'auto',
  // `siteConfig.favicon` has three consumers with different base handling, so it
  // needs one value that satisfies all of them:
  //   - valaxy/dist/shared/valaxy.Cb_HdczD.mjs:647 emits it verbatim into the raw
  //     head (no withBase), so a bare '/favicon.svg' 404s at the account root;
  //   - valaxy/client/composables/app/useValaxyHead.ts:38 applies withBase();
  //   - valaxy/client/composables/app/useValaxyApp.ts:38 resolves it against
  //     siteConfig.url for og:image/twitter:image.
  // withBase() and resolveSiteUrl() both short-circuit on absolute URLs
  // (valaxy/client/utils/path.ts:15,25), so the absolute form is the only one
  // that is correct for the verbatim consumer and un-doubled for the other two.
  // Same trade-off as `author.avatar` below.
  favicon: 'https://doc4c3.github.io/DocAceLittleHome.github.io/favicon.svg',
  author: {
    name: 'DocAcer',
    email: '1255893218@qq.com',
    link: 'https://github.com/Doc4c3',
    avatar: 'https://doc4c3.github.io/DocAceLittleHome.github.io/images/avatar.png',
  },
  social: [
    {
      name: 'RSS',
      link: '/DocAceLittleHome.github.io/atom.xml',
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
      link: 'mailto:1255893218@qq.com',
      icon: 'i-ri-mail-line',
      color: '#8E71C1',
    },
  ],

  search: {
    enable: false,
  },
})
