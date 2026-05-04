<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">修改管理员密码</h1>
        <p class="page-subtitle">新密码至少 8 位，保存成功后表单会自动清空。</p>
      </div>
    </div>

    <el-card class="password-card" shadow="never">
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="当前密码" required>
          <el-input v-model="form.currentPassword" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新密码" required>
          <el-input v-model="form.newPassword" type="password" show-password autocomplete="new-password" minlength="8" @keyup.enter="submit" />
        </el-form-item>
        <el-button type="primary" :loading="loading" @click="submit">保存</el-button>
      </el-form>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'

import { changePassword } from '@/api/auth'
import { errorMessage } from '@/api/http'

const loading = ref(false)
const form = reactive({ currentPassword: '', newPassword: '' })

async function submit() {
  if (!form.currentPassword || !form.newPassword) {
    ElMessage.error('请完整填写密码字段')
    return
  }
  if (form.newPassword.trim().length < 8) {
    ElMessage.error('新密码至少 8 位')
    return
  }
  loading.value = true
  try {
    const result = await changePassword(form.currentPassword, form.newPassword)
    ElMessage.success(result.message || '密码修改成功')
    form.currentPassword = ''
    form.newPassword = ''
  } catch (error) {
    ElMessage.error(errorMessage(error, '保存失败'))
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.password-card {
  max-width: 520px;
}
</style>
