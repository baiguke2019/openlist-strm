import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Tasks from '../views/Tasks.vue'
import Configs from '../views/Configs.vue'
import Login from '../views/Login.vue'
import { authState, fetchAuthStatus, safeRedirect } from '../auth'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { public: true }
  },
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/tasks',
    name: 'Tasks',
    component: Tasks
  },
  {
    path: '/configs',
    name: 'Configs',
    component: Configs
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach(async (to) => {
  try {
    await fetchAuthStatus()
  } catch {
    // 状态接口不可用时交给后端 401 兜底
    return true
  }

  const needsLogin = authState.enabled && !authState.authenticated

  if (to.meta.public) {
    return needsLogin ? true : safeRedirect(to.query.redirect)
  }

  if (needsLogin) {
    return { path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
  }
  return true
})

export default router
