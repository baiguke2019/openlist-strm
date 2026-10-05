<template>
  <main class="login-page">
    <div class="login-theme">
      <ThemeSwitcher />
    </div>

    <section class="login-card" aria-labelledby="login-title">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">
          <el-icon :size="26"><VideoPlay /></el-icon>
        </div>
        <h1 id="login-title" class="brand-title">OpenList-STRM</h1>
        <p class="brand-subtitle">管理面板登录</p>
      </div>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        size="large"
        class="login-form"
        @submit.prevent="handleSubmit"
      >
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model.trim="form.username"
            placeholder="请输入用户名"
            autocomplete="username"
            :prefix-icon="User"
            autofocus
          />
        </el-form-item>

        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="请输入密码"
            autocomplete="current-password"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>

        <el-alert
          v-if="errorMessage"
          :title="errorMessage"
          type="error"
          :closable="false"
          show-icon
          class="login-error"
          role="alert"
        />

        <el-button
          type="primary"
          native-type="submit"
          class="login-submit"
          :loading="submitting"
        >
          登录
        </el-button>
      </el-form>
    </section>
  </main>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { User, Lock } from '@element-plus/icons-vue'
import ThemeSwitcher from '../components/ThemeSwitcher.vue'
import { login, safeRedirect } from '../auth'

const route = useRoute()
const router = useRouter()

const formRef = ref()
const submitting = ref(false)
const errorMessage = ref('')

const form = reactive({
  username: '',
  password: ''
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

async function handleSubmit() {
  if (submitting.value) return
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  errorMessage.value = ''
  try {
    await login(form.username, form.password)
    await router.replace(safeRedirect(route.query.redirect))
  } catch (error) {
    errorMessage.value = error.message
    form.password = ''
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  position: relative;
  background:
    radial-gradient(circle at 15% 20%, rgba(var(--color-primary-rgb), 0.18) 0%, transparent 45%),
    radial-gradient(circle at 85% 80%, rgba(var(--color-primary-rgb), 0.12) 0%, transparent 40%),
    linear-gradient(135deg, var(--color-bg-start) 0%, var(--color-bg-end) 100%);
}

.login-theme {
  position: absolute;
  top: 24px;
  right: 24px;
}

.login-card {
  width: 100%;
  max-width: 400px;
  padding: 40px 36px 36px;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid rgba(var(--color-primary-rgb), 0.12);
  border-radius: 24px;
  box-shadow: 0 20px 48px rgba(var(--color-primary-rgb), 0.14);
}

.brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  margin-bottom: 28px;
  text-align: center;
}

.brand-mark {
  width: 52px;
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 16px;
  color: #FFFFFF;
  background: var(--color-primary);
  box-shadow: 0 8px 20px rgba(var(--color-primary-rgb), 0.35);
  margin-bottom: 8px;
}

.brand-title {
  font-size: 24px;
  font-weight: 400;
  color: var(--color-text);
  letter-spacing: 0.3px;
}

.brand-subtitle {
  font-size: 14px;
  color: var(--color-text-muted);
}

.login-form :deep(.el-form-item__label) {
  color: var(--color-text-secondary);
  font-weight: 600;
}

.login-error {
  margin-bottom: 18px;
}

.login-submit {
  width: 100%;
  margin-top: 4px;
  height: 44px;
  font-size: 15px;
  font-weight: 600;
  border-radius: 12px;
}

@media (max-width: 480px) {
  .login-card {
    padding: 32px 22px 26px;
    border-radius: 20px;
  }
}
</style>
