<template>
  <el-tag :type="tagType" effect="light" round>{{ text }}</el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  status?: string
  text?: string
}>()

const normalized = computed(() => (props.status || 'UNKNOWN').toUpperCase())

const text = computed(() => {
  if (props.text) return props.text
  switch (normalized.value) {
    case 'RUNNING':
      return '运行中'
    case 'STOPPED':
      return '已停止'
    case 'EXITED':
      return '已退出'
    case 'STARTING':
      return '启动中'
    case 'STOPPING':
      return '停止中'
    case 'BACKOFF':
      return '启动失败(重试中)'
    case 'FATAL':
      return '启动失败'
    default:
      return '未知'
  }
})

const tagType = computed(() => {
  switch (normalized.value) {
    case 'RUNNING':
      return 'success'
    case 'STOPPED':
    case 'EXITED':
      return 'info'
    case 'STARTING':
    case 'STOPPING':
      return 'warning'
    default:
      return 'danger'
  }
})
</script>
