<template>
  <router-view v-if="route.meta.public" />
  <AdminLayout v-else />
</template>

<script setup lang="ts">
import { useRoute } from 'vue-router'

import AdminLayout from '@/layouts/AdminLayout.vue'

const route = useRoute()
</script>
