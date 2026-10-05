import { reactive } from 'vue'
import axios from 'axios'

const http = axios.create({ baseURL: '/api/auth', timeout: 15000 })

export const authState = reactive({
  loaded: false,
  enabled: false,
  authenticated: false,
  username: ''
})

function applyStatus(data) {
  authState.loaded = true
  authState.enabled = Boolean(data.auth_enabled)
  authState.authenticated = Boolean(data.authenticated)
  authState.username = data.username || ''
}

export async function fetchAuthStatus(force = false) {
  if (authState.loaded && !force) return authState
  const { data } = await http.get('/status')
  applyStatus(data)
  return authState
}

export async function login(username, password) {
  try {
    const { data } = await http.post('/login', { username, password })
    applyStatus(data)
  } catch (error) {
    error.message = error.response?.data?.error || '登录失败，请稍后再试'
    throw error
  }
}

export async function logout() {
  try {
    await http.post('/logout')
  } finally {
    authState.authenticated = false
    authState.username = ''
  }
}

export function safeRedirect(target) {
  return typeof target === 'string' && target.startsWith('/') && !target.startsWith('//') ? target : '/'
}

export function markSessionExpired() {
  authState.authenticated = false
  authState.username = ''
}
