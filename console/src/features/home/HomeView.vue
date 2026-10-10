<script setup lang="ts">
import { t } from '../../app/i18n.ts'
</script>
<template>
  <section>
    <h1 tabindex="-1">{{ t('home.title') }}</h1>
    <p>{{ t('app.name') }}</p>
    <p>{{ t('home.disconnected') }}</p>
  </section>
</template>
