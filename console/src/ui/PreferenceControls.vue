<script setup lang="ts">
import { t } from '../app/i18n.ts'
import { localeOptions, themeOptions, densityOptions } from '../app/keys.ts'
import type { Locale, Theme, Density } from '../app/locale.ts'
defineProps<{ locale: Locale; theme: Theme; density: Density }>()
const emit = defineEmits<{
  locale: [value: Locale]
  theme: [value: Theme]
  density: [value: Density]
}>()
function languageChanged(event: Event): void {
  const value = event.target instanceof HTMLSelectElement ? event.target.value : ''
  if (value === 'en' || value === 'vi') emit('locale', value)
}
function themeChanged(event: Event): void {
  const value = event.target instanceof HTMLSelectElement ? event.target.value : ''
  if (value === 'light' || value === 'dark' || value === 'system') emit('theme', value)
}
function densityChanged(event: Event): void {
  const value = event.target instanceof HTMLSelectElement ? event.target.value : ''
  if (value === 'comfortable' || value === 'compact') emit('density', value)
}
</script>
<template>
  <div class="preferences">
    <label for="language"
      >{{ t('preferences.language') }}
      <select id="language" :value="locale" @change="languageChanged">
        <option v-for="option in localeOptions" :key="option.value" :value="option.value">
          {{ t(option.key) }}
        </option>
      </select>
    </label>
    <label for="theme"
      >{{ t('preferences.theme') }}
      <select id="theme" :value="theme" @change="themeChanged">
        <option v-for="option in themeOptions" :key="option.value" :value="option.value">
          {{ t(option.key) }}
        </option>
      </select>
    </label>
    <label for="density"
      >{{ t('preferences.density') }}
      <select id="density" :value="density" @change="densityChanged">
        <option v-for="option in densityOptions" :key="option.value" :value="option.value">
          {{ t(option.key) }}
        </option>
      </select>
    </label>
  </div>
</template>
