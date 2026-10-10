import { createRouter, createWebHistory } from 'vue-router'
import type { RouterHistory } from 'vue-router'
import { fatal } from './fatal.ts'
export function createConsoleRouter(history: RouterHistory = createWebHistory('/')) {
  const router = createRouter({
    history,
    routes: [
      { path: '/', name: 'home', component: () => import('../features/home/HomeView.vue') },
      {
        path: '/:pathMatch(.*)*',
        name: 'not-found',
        component: () => import('../features/not-found/NotFoundView.vue'),
      },
    ],
  })
  router.onError((cause) => {
    fatal.fail(cause)
  })
  return router
}
