<template>
  <el-container class="admin-shell">
    <el-header class="admin-header">
      <div class="brand" @click="router.push('/projects')">
        <span class="brand-mark">SP</span>
        <span class="brand-text">SupervisorPanel</span>
      </div>

      <el-menu class="nav-menu" mode="horizontal" :ellipsis="false" :default-active="activePath" router>
        <el-menu-item index="/projects">项目列表</el-menu-item>
        <el-menu-item index="/system/status">系统状态</el-menu-item>
        <el-menu-item index="/account/password">修改密码</el-menu-item>
      </el-menu>

      <el-popover placement="bottom-end" trigger="click" width="320" @show="loadUpdateStatus">
        <template #reference>
          <el-badge :hidden="!updateStatus?.update_available" is-dot>
            <el-button :type="updateStatus?.update_available ? 'danger' : 'primary'" plain :loading="checkingUpdate">
              更新
            </el-button>
          </el-badge>
        </template>

        <div class="update-panel">
          <div class="update-row">
            <span>当前版本</span>
            <strong>{{ updateStatus?.current_version || '-' }}</strong>
          </div>
          <div class="update-row">
            <span>最新版本</span>
            <strong>{{ updateStatus?.latest_version || '-' }}</strong>
          </div>
          <div class="update-row">
            <span>检测时间</span>
            <span>{{ updateCheckedAt }}</span>
          </div>
          <el-alert
            v-if="updateStatus?.error"
            class="update-alert"
            :title="updateStatus.error"
            type="warning"
            show-icon
            :closable="false"
          />
          <el-alert
            v-else-if="updateStatus?.update_available"
            class="update-alert"
            :title="`发现新版本 ${updateStatus.latest_version}`"
            type="success"
            show-icon
            :closable="false"
          />
          <el-alert v-else class="update-alert" title="当前已是最新版本" type="info" show-icon :closable="false" />
          <div class="update-actions">
            <el-button :loading="checkingUpdate" @click="manualCheckUpdate">检测</el-button>
            <el-button
              type="danger"
              :disabled="!updateStatus?.update_available || updateStatus?.upgrading"
              :loading="upgradingPanel || updateStatus?.upgrading"
              @click="confirmUpgradePanel"
            >
              一键升级
            </el-button>
          </div>
        </div>
      </el-popover>
      <el-button type="warning" plain :loading="restartingSupervisor" @click="confirmRestartSupervisor">重启</el-button>
      <el-button plain @click="logout">退出</el-button>
    </el-header>

    <el-main class="admin-main">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'

import { errorMessage } from '@/api/http'
import { checkForUpdate, getUpdateStatus, restartSupervisor, upgradePanel } from '@/api/system'
import type { UpdateStatus } from '@/types/api'

const route = useRoute()
const router = useRouter()
const restartingSupervisor = ref(false)
const checkingUpdate = ref(false)
const upgradingPanel = ref(false)
const updateStatus = ref<UpdateStatus>()
let updateTimer: number | undefined

const activePath = computed(() => {
  if (route.path.startsWith('/account/password')) return '/account/password'
  if (route.path.startsWith('/system/status')) return '/system/status'
  return '/projects'
})

const updateCheckedAt = computed(() => {
  if (!updateStatus.value?.checked_at) return '-'
  return new Date(updateStatus.value.checked_at).toLocaleString('zh-CN')
})

onMounted(() => {
  void loadUpdateStatus()
  updateTimer = window.setInterval(() => {
    if (!document.hidden) void loadUpdateStatus(false)
  }, 10 * 60 * 1000)
})

onBeforeUnmount(() => {
  if (updateTimer) window.clearInterval(updateTimer)
})

async function confirmRestartSupervisor() {
  try {
    await ElMessageBox.confirm(
      '该操作将提交重启 Supervisor 服务命令，可能短暂影响所有由 Supervisor 管理的项目。确认继续？',
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
    ElMessage.success(result.message || '已提交重启 Supervisor 命令')
  } catch (error) {
    ElMessage.error(errorMessage(error, '重启 Supervisor 失败'))
  } finally {
    restartingSupervisor.value = false
  }
}

async function loadUpdateStatus(showError = false) {
  try {
    const result = await getUpdateStatus()
    updateStatus.value = result.update
  } catch (error) {
    if (showError) ElMessage.error(errorMessage(error, '加载更新状态失败'))
  }
}

async function manualCheckUpdate() {
  checkingUpdate.value = true
  try {
    const result = await checkForUpdate()
    updateStatus.value = result.update
    if (result.update.update_available) {
      ElMessage.warning(`发现新版本 ${result.update.latest_version}`)
    } else {
      ElMessage.success('当前已是最新版本')
    }
  } catch (error) {
    ElMessage.error(errorMessage(error, '检测更新失败'))
  } finally {
    checkingUpdate.value = false
  }
}

async function confirmUpgradePanel() {
  if (!updateStatus.value?.update_available) return
  try {
    await ElMessageBox.confirm(
      `将升级到 ${updateStatus.value.latest_version}，服务会自动重启，页面可能短暂不可用。确认继续？`,
      '一键升级',
      {
        confirmButtonText: '确认升级',
        cancelButtonText: '取消',
        type: 'warning',
      },
    )
  } catch {
    return
  }

  upgradingPanel.value = true
  try {
    const result = await upgradePanel()
    updateStatus.value = result.update
    ElMessage.success(result.message || '已提交升级任务')
  } catch (error) {
    ElMessage.error(errorMessage(error, '提交升级失败'))
  } finally {
    upgradingPanel.value = false
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

.update-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.update-row {
  display: flex;
  justify-content: space-between;
  gap: 14px;
  color: var(--el-text-color-regular);
  font-size: 13px;
}

.update-alert {
  margin-top: 2px;
}

.update-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
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
