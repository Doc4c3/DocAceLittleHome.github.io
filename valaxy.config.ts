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
