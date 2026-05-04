import { createRouter, createWebHistory } from 'vue-router'

import LoginView from '@/views/LoginView.vue'
import ProjectsView from '@/views/ProjectsView.vue'
import ProjectDetailView from '@/views/ProjectDetailView.vue'
import ProjectLogsView from '@/views/ProjectLogsView.vue'
import EditFileView from '@/views/EditFileView.vue'
import PasswordView from '@/views/PasswordView.vue'
import { getMe } from '@/api/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    { path: '/', redirect: '/projects' },
    { path: '/projects', name: 'projects', component: ProjectsView },
    { path: '/projects/:id(\\d+)', name: 'project-detail', component: ProjectDetailView },
    { path: '/projects/:id(\\d+)/logs', name: 'project-logs', component: ProjectLogsView },
    { path: '/projects/:id(\\d+)/files/edit', name: 'edit-file', component: EditFileView },
    { path: '/account/password', name: 'password', component: PasswordView },
    { path: '/:pathMatch(.*)*', redirect: '/projects' },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.public) {
    return true
  }
  try {
    await getMe()
    return true
  } catch {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
})

export default router
