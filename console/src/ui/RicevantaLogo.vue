<script setup lang="ts">
import { t } from '../app/i18n.ts'
</script>
<template>
  <span class="logo" role="img" :aria-label="t('app.logo')">
    <img
      class="logo-light"
      src="/brand/horizontal-color.svg"
      alt=""
      aria-hidden="true"
      width="180"
      height="64"
    />
    <img
      class="logo-dark"
      src="/brand/horizontal-dark.svg"
      alt=""
      aria-hidden="true"
      width="180"
      height="64"
    />
  </span>
</template>
