// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2024-11-01',
  devtools: { enabled: true },
  modules: ['./auth0'],
  runtimeConfig: {
    auth0: {
      domain: '', // isoverridden by NUXT_AUTH0_DOMAIN environment variable
      clientId: '', // isoverridden by NUXT_AUTH0_CLIENT_ID environment variable
      clientSecret: '', // isoverridden by NUXT_AUTH0_CLIENT_SECRET environment variable
      sessionSecret: '', // isoverridden by NUXT_AUTH0_SESSION_SECRET environment variable
      appBaseUrl: '', // isoverridden by NUXT_AUTH0_APP_BASE_URL environment variable
    },
  },
  app: {
    head: {
      script: [
        {
          src: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
          integrity:
            'sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz',
          crossorigin: 'anonymous',
        },
      ],
      link: [
        {
          rel: 'stylesheet',
          href: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
          integrity:
            'sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH',
          crossorigin: 'anonymous',
        },
      ],
    },
  },
});
