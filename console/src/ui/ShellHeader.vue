<script setup lang="ts">
import { RouterLink } from 'vue-router'
import RicevantaLogo from './RicevantaLogo.vue'
import { t } from '../app/i18n.ts'
</script>
<template>
  <header class="shell-header">
    <RicevantaLogo />
    <nav :aria-label="t('nav.label')">
      <RouterLink :to="{ name: 'home' }">{{ t('nav.home') }}</RouterLink>
    </nav>
    <slot />
  </header>
</template>
