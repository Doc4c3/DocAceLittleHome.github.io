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
