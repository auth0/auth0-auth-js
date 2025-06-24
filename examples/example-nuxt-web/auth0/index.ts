import {
  defineNuxtModule,
  createResolver,
  addServerHandler,
  addServerPlugin,
  addRouteMiddleware
} from '@nuxt/kit';

export default defineNuxtModule({
  meta: {
    name: 'auth0-nuxt',
    configKey: 'auth0',
  },
  async setup(options, nuxt) {
    const resolver = createResolver(import.meta.url);

    addServerPlugin(resolver.resolve('./server/plugins/auth.server'));

    addRouteMiddleware({ name: 'auth0', path: resolver.resolve('./middleware/auth.server'), global: true });

    addServerHandler({
      handler: resolver.resolve('./server/api/auth/login.get'),
      route: '/auth/login',
      method: 'get',
    });

    addServerHandler({
      handler: resolver.resolve('./server/api/auth/callback.get'),
      route: '/auth/callback',
      method: 'get',
    });

    addServerHandler({
      handler: resolver.resolve('./server/api/auth/logout.get'),
      route: '/auth/logout',
      method: 'get',
    });

    addServerHandler({
      handler: resolver.resolve('./server/api/auth/profile.get'),
      route: '/auth/profile',
      method: 'get',
    });

    nuxt.hook('imports:dirs', (dirs) => {
      dirs.push(resolver.resolve('./composables'))
    })
  },
});
