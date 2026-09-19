<template>
  <el-card shadow="never">
    <template #header>
      <div class="time-header">
        <span>服务器时间</span>
        <el-button :loading="loading" :disabled="submitting" @click="loadTime">刷新时间</el-button>
      </div>
    </template>
    <div class="time-content">
      <div class="time-summary">
        <div>
          <div class="server-clock mono">{{ timeText }}</div>
          <div class="muted">时区：{{ status?.timezone || '-' }} · 每 5 秒刷新</div>
        </div>
        <div class="time-tags">
          <el-tag :type="syncTagType">{{ syncText }}</el-tag>
          <span class="muted">自动同步：{{ status?.available ? (status.ntp_enabled ? '已启用' : '未启用') : '未知' }}</span>
        </div>
      </div>
      <div v-if="status" class="muted">
        当前配置：{{ status.source_mode === 'custom' ? `自定义 · ${status.custom_server}` : '沿用系统 NTP 配置' }}
        <span v-if="status.active_server"> · 当前连接：{{ status.active_server }}</span>
      </div>
      <el-alert v-if="loadError || status?.message" :title="loadError || status?.message" type="warning" show-icon :closable="false" />
      <el-form label-position="top" @submit.prevent="confirmSync">
        <el-form-item label="校准时间源">
          <el-radio-group v-model="mode" :disabled="submitting">
            <el-radio-button value="system">系统配置</el-radio-button>
            <el-radio-button value="custom">自定义 NTP</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="mode === 'custom'" label="NTP 服务器">
          <el-input v-model="customServer" :disabled="submitting" maxlength="253" placeholder="例如：ntp.example.com 或 IP 地址" />
        </el-form-item>
        <p v-if="mode === 'custom' && !status?.custom_available" class="muted">
          自定义时间源需要正在运行的 systemd-timesyncd。其他 NTP 服务请先在服务器配置，再选择“系统配置”。
        </p>
        <p v-else-if="mode === 'custom'" class="muted">保存后持续使用此时间源；系统网络配置也可能提供其他 NTP 服务器，实际连接见上方状态。</p>
        <p v-else class="muted">使用服务器已有的 NTP 配置；如曾在面板设置自定义时间源，本次将恢复系统配置。</p>
        <el-button type="primary" native-type="submit" :loading="submitting" :disabled="!canSubmit">校准时间</el-button>
      </el-form>
      <el-alert v-if="resultText" :title="resultText" :type="resultType" show-icon :closable="false" />
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { errorMessage } from '@/api/http'
import { getSystemTime, syncSystemTime } from '@/api/system'
import type { SystemTime } from '@/types/api'

const status = ref<SystemTime>()
const loading = ref(false)
const submitting = ref(false)
const loadError = ref('')
const mode = ref<'system' | 'custom'>('system')
const customServer = ref('')
const resultText = ref('')
const resultType = ref<'info' | 'warning' | 'error'>('info')
let initialized = false
let timer: number | undefined
let waitingSince: number | undefined
let disposed = false
let generation = 0

const timeText = computed(() => status.value?.server_time.replace('T', ' ') || '-')
const syncText = computed(() => {
  if (loadError.value || !status.value?.available) return '同步状态未知'
  return status.value.synchronized ? '系统报告已同步' : '尚未同步'
})
const syncTagType = computed(() => {
  if (loadError.value || !status.value?.available) return 'info'
  return status.value.synchronized ? 'success' : 'warning'
})
const canSubmit = computed(() => !loadError.value && status.value?.available &&
  (mode.value === 'system' || (status.value.custom_available && customServer.value.trim().length > 0)))

onMounted(() => {
  void loadTime()
  timer = window.setInterval(() => {
    if (!document.hidden) void loadTime()
  }, 5000)
})

onBeforeUnmount(() => {
  disposed = true
  if (timer) window.clearInterval(timer)
})

async function loadTime() {
  if (loading.value || submitting.value) return
  const current = generation
  loading.value = true
  try {
    const response = await getSystemTime()
    if (disposed || current !== generation) return
    status.value = response.time
    loadError.value = ''
    if (!initialized) {
      mode.value = response.time.source_mode
      customServer.value = response.time.custom_server
      initialized = true
    }
    if (waitingSince !== undefined && performance.now() - waitingSince > 120000) {
      if (!response.time.synchronized) {
        resultType.value = 'warning'
        resultText.value = '同步命令已提交，但尚未确认时间同步。请检查 NTP 服务器地址、网络连接及同步服务；自动同步仍会继续。'
      }
      waitingSince = undefined
    }
  } catch (error) {
    if (disposed || current !== generation) return
    loadError.value = errorMessage(error, '读取服务器时间失败') + '；显示的时间可能已过期'
  } finally {
    loading.value = false
  }
}

async function confirmSync() {
  if (!canSubmit.value || submitting.value) return
  submitting.value = true
  const request = { mode: mode.value, server: mode.value === 'custom' ? customServer.value.trim() : '' }
  try {
    await ElMessageBox.confirm(
      `将启用自动校准，${request.mode === 'custom' ? `时间源为 ${request.server}` : '沿用系统 NTP 配置'}。服务器时间变化可能影响定时任务、日志和登录会话。确认继续？`,
      '校准服务器时间',
      { confirmButtonText: '确认校准', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    submitting.value = false
    return
  }
  if (disposed) return
  generation += 1
  waitingSince = undefined
  resultText.value = ''
  try {
    const response = await syncSystemTime(request)
    if (disposed) return
    status.value = response.time
    loadError.value = ''
    resultType.value = 'info'
    resultText.value = response.message || '已提交自动同步请求，请查看系统同步状态'
    waitingSince = performance.now()
  } catch (error) {
    if (disposed) return
    resultType.value = 'error'
    resultText.value = errorMessage(error, '时间校准失败')
  } finally {
    submitting.value = false
    if (!disposed) void loadTime()
  }
}
</script>

<style scoped>
.time-header, .time-summary, .time-tags {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}
.time-content { display: grid; gap: 16px; }
.time-content .el-form { max-width: 620px; }
.time-content .muted { font-size: 13px; line-height: 1.7; overflow-wrap: anywhere; }
.server-clock { font-size: clamp(17px, 3vw, 26px); font-weight: 650; overflow-wrap: anywhere; }
</style>
