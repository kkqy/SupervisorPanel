<template>
  <el-container class="admin-shell">
    <el-header class="admin-header">
      <div class="brand" @click="router.push('/projects')">
        <span class="brand-mark">SP</span>
        <span class="brand-text">SupervisorPanel</span>
      </div>

      <el-menu class="nav-menu" mode="horizontal" :ellipsis="false" :default-active="activePath" router>
        <el-menu-item index="/projects">项目列表</el-menu-item>
        <el-menu-item index="/account/password">修改密码</el-menu-item>
      </el-menu>

      <el-button type="warning" plain :loading="restartingSupervisor" @click="confirmRestartSupervisor">重启 Supervisor</el-button>
      <el-button plain @click="logout">退出</el-button>
    </el-header>

    <el-main class="admin-main">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'

import { errorMessage } from '@/api/http'
import { restartSupervisor } from '@/api/system'

const route = useRoute()
const router = useRouter()
const restartingSupervisor = ref(false)

const activePath = computed(() => (route.path.startsWith('/account/password') ? '/account/password' : '/projects'))

async function confirmRestartSupervisor() {
  try {
    await ElMessageBox.confirm(
      '该操作将重启 Supervisor 服务，可能短暂影响所有由 Supervisor 管理的项目。确认继续？',
      '重启 Supervisor',
      {
        confirmButtonText: '确认重启',
        cancelButtonText: '取消',
        type: 'warning',
      },
    )
  } catch {
    return
  }

  restartingSupervisor.value = true
  try {
    const result = await restartSupervisor()
    ElMessage.success(result.message || 'Supervisor 已重启')
  } catch (error) {
    ElMessage.error(errorMessage(error, '重启 Supervisor 失败'))
  } finally {
    restartingSupervisor.value = false
  }
}

function logout() {
  window.location.href = '/logout'
}
</script>

<style scoped>
.admin-shell {
  min-height: 100vh;
}

.admin-header {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  align-items: center;
  gap: 18px;
  border-bottom: 1px solid var(--el-border-color-light);
  background: #fff;
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-width: 220px;
  cursor: pointer;
  user-select: none;
}

.brand-mark {
  display: inline-grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border-radius: 10px;
  background: var(--el-color-primary);
  color: #fff;
  font-weight: 700;
}

.brand-text {
  font-size: 18px;
  font-weight: 700;
}

.nav-menu {
  flex: 1;
  border-bottom: 0;
}

.admin-main {
  width: min(1280px, 100%);
  margin: 0 auto;
  padding: 20px;
}

@media (max-width: 720px) {
  .admin-header {
    height: auto;
    flex-wrap: wrap;
    padding: 10px 14px;
  }

  .brand {
    min-width: 0;
    flex: 1;
  }

  .nav-menu {
    order: 3;
    width: 100%;
  }

  .admin-main {
    padding: 14px;
  }
}
</style>
