from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(template_name="recon/login.html"),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("status/", views.status_page, name="status_page"),
    path("tasks/new/", views.task_create, name="task_create"),
    path("tasks/preview-command/", views.command_preview, name="command_preview"),
    path("tasks/<uuid:task_id>/", views.task_detail, name="task_detail"),
    path("tasks/<uuid:task_id>/status/", views.task_status, name="task_status"),
    path("tasks/<uuid:task_id>/cancel/", views.task_cancel, name="task_cancel"),
    path("tasks/<uuid:task_id>/rerun/", views.task_rerun, name="task_rerun"),
    path(
        "tasks/<uuid:task_id>/report/<str:fmt>/",
        views.report_view,
        name="report_view",
    ),
    path(
        "tasks/<uuid:task_id>/artifacts/<int:artifact_id>/",
        views.artifact_download,
        name="artifact_download",
    ),
]
