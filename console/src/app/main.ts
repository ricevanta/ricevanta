import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { createConsoleRouter } from './router.ts'
import { i18n } from './i18n.ts'
import { fatal } from './fatal.ts'
import { usePreferences } from '../stores/preferences.ts'
import '../generated/tokens.css'
import '../ui/styles/base.css'
import '../ui/styles/fonts.css'
const pinia = createPinia()
const preferences = usePreferences(pinia)
let storage: Storage | undefined
try {
  storage = window.localStorage
} catch {
  /* Storage is optional. */
}
preferences.initialize(storage, navigator.languages)
i18n.global.locale.value = preferences.locale
const router = createConsoleRouter()
// ESLint cannot resolve SFC types without declarations; vue-tsc checks App.vue.
// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
const app = createApp(App)
app.config.errorHandler = (cause: unknown) => {
  fatal.fail(cause)
}
app.use(pinia).use(i18n).use(router)
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault()
  fatal.fail(event)
})
window.addEventListener('unhandledrejection', (event) => {
  event.preventDefault()
  fatal.fail(event.reason)
})
window.addEventListener('error', (event) => {
  fatal.fail(event.error)
})
router
  .isReady()
  .then(() => app.mount('#app'))
  .catch((cause: unknown) => {
    fatal.fail(cause)
    app.mount('#app')
  })
