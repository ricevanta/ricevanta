import { readonly, ref, shallowRef } from 'vue'
const failed = ref(false)
const error = shallowRef<Error | null>(null)
export const fatalError = readonly(error)
export const fatal = {
  failed: readonly(failed),
  fail(cause: unknown): void {
    error.value = new Error('Console failure', { cause })
    failed.value = true
  },
  reset(): void {
    error.value = null
    failed.value = false
  },
}
