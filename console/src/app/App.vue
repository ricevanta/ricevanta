<script setup lang="ts">
import { nextTick, useTemplateRef, watch } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import ShellHeader from '../ui/ShellHeader.vue'
import PreferenceControls from '../ui/PreferenceControls.vue'
import { usePreferences } from '../stores/preferences.ts'
import { fatal } from './fatal.ts'
import { i18n, t } from './i18n.ts'
import { routeTitles } from './keys.ts'
const preferences = usePreferences()
const route = useRoute()
const main = useTemplateRef<HTMLElement>('main')
watch(
  () =>
    [
      preferences.locale,
      preferences.theme,
      preferences.density,
      route.name,
      fatal.failed.value,
    ] as const,
  () => {
    i18n.global.locale.value = preferences.locale
    document.documentElement.lang = preferences.locale
    document.documentElement.dataset['theme'] = preferences.theme
    document.documentElement.dataset['density'] = preferences.density
    const titleKey = route.name === 'home' ? routeTitles.home : routeTitles['not-found']
    document.title = fatal.failed.value ? t('errors.title') : t(titleKey)
  },
  { immediate: true },
)
watch(
  [() => route.fullPath.split('#')[0], () => fatal.failed.value],
  async () => {
    await nextTick()
    document.querySelector<HTMLElement>('main h1')?.focus()
  },
  { immediate: true, flush: 'post' },
)
function reload(): void {
  window.location.reload()
}
function focusMain(): void {
  main.value?.focus()
}
</script>
<template>
  <a class="skip-link" href="#main" @click="focusMain">{{ t('app.skip') }}</a>
  <ShellHeader>
    <PreferenceControls
      :locale="preferences.locale"
      :theme="preferences.theme"
      :density="preferences.density"
      @locale="preferences.setLocale"
      @theme="preferences.setTheme"
      @density="preferences.setDensity"
    />
  </ShellHeader>
  <main id="main" ref="main" tabindex="-1">
    <section v-if="fatal.failed.value" role="alert">
      <h1 tabindex="-1">{{ t('errors.title') }}</h1>
      <p>{{ t('errors.message') }}</p>
      <button type="button" @click="reload">{{ t('errors.reload') }}</button>
    </section>
    <RouterView v-else />
  </main>
</template>
