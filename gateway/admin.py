"""
Admin configuration for the gateway app.
Registers key models with custom display, filtering, export, and readonly field options.
Also includes inline relations, visual tags, and data integrity checks.
"""

from django.contrib import admin, messages
from django.utils.html import format_html
from django.http import HttpResponse
import csv
from .models import LoginAudit, IPBlacklist, OTPChallenge


def export_as_csv_action(description="Export selected as CSV", fields=None, exclude=None, header=True):
    def export_as_csv(modeladmin, request, queryset):
        opts = modeladmin.model._meta
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename={opts.verbose_name_plural}.csv'
        writer = csv.writer(response)

        field_names = [field.name for field in opts.fields if (not exclude or field.name not in exclude)]
        if fields:
            field_names = fields
        if header:
            writer.writerow(field_names)

        for obj in queryset:
            writer.writerow([getattr(obj, field) for field in field_names])
        return response

    export_as_csv.short_description = description
    return export_as_csv


@admin.register(LoginAudit)
class LoginAuditAdmin(admin.ModelAdmin):
    list_display = ("user", "ip_address", "status", "timestamp", "location_display")
    list_filter = ("status", "timestamp")
    search_fields = ("user__username", "ip_address")
    ordering = ("-timestamp",)
    readonly_fields = ("user", "ip_address", "user_agent", "timestamp", "status")
    actions = [
        export_as_csv_action("Export Login Audits as CSV", fields=["user", "ip_address", "status", "timestamp"]),
        "mark_as_suspicious"
    ]

    def location_display(self, obj):
        return f"{obj.city}, {obj.country}" if obj.city and obj.country else "-"
    location_display.short_description = "Location"

    def mark_as_suspicious(self, request, queryset):
        updated = queryset.update(status='suspicious')
        self.message_user(request, f"{updated} entries marked as suspicious.", messages.WARNING)
    mark_as_suspicious.short_description = "Mark selected as suspicious"


@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "reason", "created_at", "is_active", "tag")
    list_filter = ("is_active", "created_at")
    search_fields = ("ip_address", "reason")
    ordering = ("-created_at",)
    readonly_fields = ("ip_address", "reason", "created_at")
    actions = [
        export_as_csv_action("Export IP Blacklist as CSV", fields=["ip_address", "reason", "created_at", "is_active"]),
        "toggle_blacklist_status"
    ]

    def tag(self, obj):
        if obj.is_active:
            return format_html('<span style="color: red; font-weight: bold;">Blocked</span>')
        return format_html('<span style="color: green;">Cleared</span>')
    tag.short_description = "Status"

    def toggle_blacklist_status(self, request, queryset):
        updated = 0
        for ip in queryset:
            ip.is_active = not ip.is_active
            ip.save()
            updated += 1
        self.message_user(request, f"{updated} IP(s) toggled status.", messages.SUCCESS)
    toggle_blacklist_status.short_description = "Toggle active status"


@admin.register(OTPChallenge)
class OTPChallengeAdmin(admin.ModelAdmin):
    list_display = ("user", "method", "verified", "created_at", "code_preview")
    list_filter = ("method", "verified")
    search_fields = ("user__username",)
    readonly_fields = ("code", "user", "method", "created_at")
    ordering = ("-created_at",)
    actions = [
        export_as_csv_action("Export OTP Challenges as CSV", fields=["user", "method", "verified", "created_at"]),
        "mark_verified"
    ]

    def code_preview(self, obj):
        return format_html('<code>{}</code>', obj.code)
    code_preview.short_description = "OTP Code Preview"

    def mark_verified(self, request, queryset):
        updated = queryset.update(verified=True)
        self.message_user(request, f"{updated} OTP challenge(s) marked as verified.", messages.SUCCESS)
    mark_verified.short_description = "Mark selected as verified"
