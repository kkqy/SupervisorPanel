<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">项目日志：{{ logsData?.project.name || '-' }}</h1>
        <p class="page-subtitle">日志路径：<span class="mono">{{ logsData?.log_path || '-' }}</span></p>
      </div>
      <div class="toolbar">
        <el-radio-group v-model="lines" @change="loadLogs">
          <el-radio-button :label="200">200 行</el-radio-button>
          <el-radio-button :label="500">500 行</el-radio-button>
          <el-radio-button :label="1000">1000 行</el-radio-button>
        </el-radio-group>
        <el-button :type="following ? 'warning' : 'primary'" @click="toggleFollow">{{ following ? '暂停追踪' : '开始追踪' }}</el-button>
        <el-button @click="router.push(`/projects/${projectID}`)">返回项目</el-button>
      </div>
    </div>

    <el-card v-loading="loading" shadow="never">
      <template #header>
        <div class="toolbar">
          <el-tag :type="following ? 'success' : 'info'">{{ followState }}</el-tag>
          <span class="muted">显示最近 {{ lines }} 行</span>
        </div>
      </template>
      <pre ref="logBox" class="logbox">{{ logText }}</pre>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { getLogs } from '@/api/projects'
import { errorMessage } from '@/api/http'
import type { LogsResponse } from '@/types/api'

const route = useRoute()
const router = useRouter()
const projectID = Number(route.params.id)

const loading = ref(false)
const lines = ref(200)
const logsData = ref<LogsResponse>()
const logText = ref('')
const logBox = ref<HTMLElement>()
const following = ref(false)
const followState = ref('未连接')
let source: EventSource | undefined
let offset = 0

onMounted(() => {
  void loadLogs()
  document.addEventListener('visibilitychange', handleVisibilityChange)
})

onBeforeUnmount(() => {
  stopFollow('已关闭')
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})

async function loadLogs() {
  stopFollow('未连接')
  loading.value = true
  try {
    const result = await getLogs(projectID, lines.value)
    logsData.value = result
    logText.value = result.logs || ''
    offset = result.start_offset || 0
    await scrollToBottom()
  } catch (error) {
    ElMessage.error(errorMessage(error, '加载日志失败'))
  } finally {
    loading.value = false
  }
}

function toggleFollow() {
  if (following.value) {
    stopFollow('已暂停')
    return
  }
  startFollow()
}

function startFollow() {
  if (source) source.close()
  source = new EventSource(`/projects/${projectID}/logs/stream?offset=${encodeURIComponent(String(offset))}`)
  following.value = true
  followState.value = '连接中...'

  source.addEventListener('ready', () => {
    followState.value = '实时追踪中'
  })

  source.addEventListener('log', (event) => {
    try {
      const payload = JSON.parse(event.data || '{}') as { chunk?: string; offset?: number }
      appendChunk(payload.chunk || '')
      if (typeof payload.offset === 'number') offset = payload.offset
    } catch {
      followState.value = '解析日志失败'
    }
  })

  source.addEventListener('error', () => {
    followState.value = '连接中断，自动重连中...'
  })
}

function stopFollow(state: string) {
  following.value = false
  followState.value = state
  if (source) {
    source.close()
    source = undefined
  }
}

function appendChunk(chunk: string) {
  if (!chunk) return
  logText.value += chunk
  const maxChars = 220000
  if (logText.value.length > maxChars) {
    logText.value = logText.value.slice(logText.value.length - maxChars)
  }
  void scrollToBottom()
}

async function scrollToBottom() {
  await nextTick()
  if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
}

function handleVisibilityChange() {
  if (document.hidden && following.value) {
    stopFollow('页面不可见，已自动暂停')
  }
}
</script>
