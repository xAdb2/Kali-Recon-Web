from django.contrib import admin

from .models import (
    Artifact,
    AuditEvent,
    Endpoint,
    Finding,
    ScanStep,
    ScanTask,
    Service,
)


class ScanStepInline(admin.TabularInline):
    model = ScanStep
    extra = 0
    readonly_fields = ("tool", "status", "order", "exit_code")


@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ("name", "target_ip", "url_hostname", "status", "created_at")
    list_filter = ("status", "profile")
    search_fields = ("name", "target_ip", "url_hostname")
    readonly_fields = ("id", "created_at", "started_at", "finished_at")
    inlines = [ScanStepInline]


@admin.register(ScanStep)
class ScanStepAdmin(admin.ModelAdmin):
    list_display = ("task", "order", "tool", "status", "exit_code")
    list_filter = ("status", "tool", "command_mode")


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("task", "ip", "port", "service_name", "product")


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ("task", "url", "status_code")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("task", "severity", "title", "source_tool")
    list_filter = ("severity", "confidence", "source_tool")


@admin.register(Artifact)
class ArtifactAdmin(admin.ModelAdmin):
    list_display = ("task", "name", "artifact_type", "size")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("action", "task", "actor", "created_at")
    list_filter = ("action",)
