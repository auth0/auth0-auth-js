<script setup lang="ts">
const { user, isAuthenticated } = await useAuth();

// We can also interact with the SDK like this
if (import.meta.server) {
  const auth0Client = useAuth0Client();
  const { accessToken } = await auth0Client.getAccessToken();
  console.log(accessToken);
}
</script>

<template>
  <nav class="py-2 bg-body-tertiary border-bottom">
    <div class="container d-flex flex-wrap">
      <a
        href="/"
        class="d-flex align-items-center mb-2 mb-lg-0 text-white text-decoration-none"
      >
        <img src="/img/auth0.png" width="36" height="36" alt="Auth0 logo" />
      </a>
      <ul class="nav me-auto">
        <li class="nav-item">
          <a
            href="/public"
            class="nav-link link-body-emphasis px-2 active"
            aria-current="page"
            >Public Page</a
          >
        </li>
        <li class="nav-item">
          <a
            href="/private"
            class="nav-link link-body-emphasis px-2 active"
            aria-current="page"
            >Private Page</a
          >
        </li>
      </ul>
      <ul class="nav">
        <li class="nav-item">
          <a
            v-if="isAuthenticated"
            class="nav-link link-body-emphasis px-2"
            href="/auth/logout"
            >Log out ({{ user?.name }})</a
          >

          <a
            v-if="!isAuthenticated"
            class="nav-link link-body-emphasis px-2"
            href="/auth/login"
            >Log in</a
          >
        </li>
      </ul>
    </div>
  </nav>
  <div class="container py-4">
    <NuxtPage />
  </div>
</template>
