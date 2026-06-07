<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统状态</h1>
        <p class="page-subtitle">采集时间：{{ collectedAtText }}</p>
      </div>
      <div class="toolbar">
        <el-button :loading="loading" @click="loadStatus">刷新</el-button>
      </div>
    </div>

    <el-alert v-if="errorText" :title="errorText" type="error" show-icon :closable="false" />

    <div class="metric-grid">
      <el-card shadow="never">
        <template #header>CPU</template>
        <el-progress type="dashboard" :percentage="cpuPercent" />
        <div class="metric-value">{{ cpuPercent }}%</div>
      </el-card>

      <el-card shadow="never">
        <template #header>内存</template>
        <el-progress type="dashboard" :percentage="memoryPercent" />
        <div class="metric-value">{{ memoryPercent }}%</div>
        <div class="resource-summary">{{ memorySummary }}</div>
      </el-card>

      <el-card shadow="never">
        <template #header>硬盘</template>
        <el-progress type="dashboard" :percentage="diskPercent" />
        <div class="metric-value">{{ diskPercent }}%</div>
        <div class="resource-summary">{{ diskSummary }}</div>
        <div class="resource-summary mono">{{ status?.disk.path || '-' }}</div>
      </el-card>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { errorMessage } from '@/api/http'
import { getSystemStatus } from '@/api/system'
import type { SystemSnapshot } from '@/types/api'

const loading = ref(false)
const errorText = ref('')
const status = ref<SystemSnapshot>()
let timer: number | undefined

const collectedAtText = computed(() => {
  if (!status.value?.collected_at) return '-'
  return new Date(status.value.collected_at).toLocaleString('zh-CN')
})

const cpuPercent = computed(() => percent(status.value?.cpu.usage_percent))
const memoryPercent = computed(() => percent(status.value?.memory.usage_percent))
const diskPercent = computed(() => percent(status.value?.disk.usage_percent))

const memorySummary = computed(() => {
  const memory = status.value?.memory
  if (!memory) return '-'
  return `${formatBytes(memory.used_bytes)} / ${formatBytes(memory.total_bytes)}`
})

const diskSummary = computed(() => {
  const disk = status.value?.disk
  if (!disk) return '-'
  return `${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)}`
})

onMounted(() => {
  void loadStatus()
  timer = window.setInterval(() => {
    if (!document.hidden) void loadStatus()
  }, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})

async function loadStatus() {
  loading.value = true
  try {
    const result = await getSystemStatus()
    status.value = result.system
    errorText.value = ''
  } catch (error) {
    errorText.value = errorMessage(error, '加载系统状态失败')
  } finally {
    loading.value = false
  }
}

function percent(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0
  return Math.min(100, Math.max(0, Math.round(value)))
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`
}
</script>
