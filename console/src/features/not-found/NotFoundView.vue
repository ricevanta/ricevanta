<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { t } from '../../app/i18n.ts'
</script>
<template>
  <section>
    <h1 tabindex="-1">{{ t('notFound.title') }}</h1>
    <p>{{ t('notFound.message') }}</p>
    <RouterLink :to="{ name: 'home' }">{{ t('notFound.home') }}</RouterLink>
  </section>
</template>
