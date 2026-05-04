<template>
  <main class="login-page">
    <el-card class="login-card" shadow="always">
      <div class="login-head">
        <div class="login-mark">SP</div>
        <h1>SupervisorPanel</h1>
        <p>管理员登录</p>
      </div>

      <el-form ref="formRef" :model="form" label-position="top" @submit.prevent="submit">
        <el-form-item label="用户名" required>
          <el-input v-model.trim="form.username" autocomplete="username" size="large" />
        </el-form-item>
        <el-form-item label="密码" required>
          <el-input v-model="form.password" type="password" autocomplete="current-password" show-password size="large" @keyup.enter="submit" />
        </el-form-item>
        <el-button class="login-button" type="primary" size="large" :loading="loading" @click="submit">登录</el-button>
      </el-form>
    </el-card>
  </main>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { login } from '@/api/auth'
import { errorMessage } from '@/api/http'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const form = reactive({ username: '', password: '' })

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.error('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const result = await login(form.username, form.password)
    ElMessage.success(result.message || '登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/projects'
    await router.replace(redirect)
  } catch (error) {
    ElMessage.error(errorMessage(error, '登录失败'))
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: grid;
  min-height: 100vh;
  place-items: center;
  padding: 20px;
  background: linear-gradient(135deg, #eef4ff 0%, #f7f8fb 48%, #ffffff 100%);
}

.login-card {
  width: min(420px, 100%);
}

.login-head {
  margin-bottom: 24px;
  text-align: center;
}

.login-mark {
  display: inline-grid;
  width: 52px;
  height: 52px;
  margin-bottom: 12px;
  place-items: center;
  border-radius: 14px;
  background: var(--el-color-primary);
  color: #fff;
  font-size: 18px;
  font-weight: 800;
}

.login-head h1 {
  margin: 0;
  font-size: 28px;
}

.login-head p {
  margin: 8px 0 0;
  color: var(--el-text-color-secondary);
}

.login-button {
  width: 100%;
}
</style>
