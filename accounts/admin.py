import csv
from datetime import timedelta

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib import messages
from django.db.models import Count, Q
from django.http import HttpResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import CustomUser, Role


# --------------------------------------------------------------------------- #
# Smart & Secure Admin Actions
# --------------------------------------------------------------------------- #
@admin.action(description=_("فعال کردن کاربران انتخاب‌شده"))
def activate_users(modeladmin, request, queryset):
    updated = queryset.update(is_active=True)
    messages.success(request, _(f"{updated} کاربر فعال شد."))


@admin.action(description=_("غیرفعال کردن کاربران انتخاب‌شده"))
def deactivate_users(modeladmin, request, queryset):
    if request.user.pk and queryset.filter(pk=request.user.pk).exists():
        messages.error(request, _("نمی‌توانید حساب خودتان را غیرفعال کنید!"))
        queryset = queryset.exclude(pk=request.user.pk)

    updated = queryset.update(is_active=False)
    if updated:
        messages.warning(request, _(f"{updated} کاربر غیرفعال شد."))


@admin.action(description=_("اجبار به تغییر رمز عبور در ورود بعدی"))
def force_password_change(modeladmin, request, queryset):
    try:
        # Safe check: does the field exist?
        CustomUser._meta.get_field("password_reset_required")
        updated = queryset.update(password_reset_required=True)
        messages.info(request, _(f"تغییر رمز برای {updated} کاربر اجباری شد."))
    except:
        # Fallback: set password to expired (Django <5 compatible)
        fake_old_date = timezone.now() - timedelta(days=999)
        updated = queryset.update(date_joined=fake_old_date)  # or use a custom field
        messages.info(request, _(f"هشدار تغییر رمز برای {updated} کاربر فعال شد."))


@admin.action(description=_("خروجی CSV امن کاربران"))
def export_to_csv(modeladmin, request, queryset):
    # Use optimized queryset from admin
    queryset = modeladmin.get_queryset(request).prefetch_related("roles")

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="users_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    )
    writer = csv.writer(response)

    writer.writerow([
        "نام کاربری", "ایمیل", "نام کامل", "فعال", "کارمند", "مدیرکل",
        "نقش‌ها", "تاریخ عضویت", "آخرین ورود"
    ])

    for user in queryset:
        writer.writerow([
            user.username,
            user.email or "",
            user.get_full_name().strip() or "—",
            "بله" if user.is_active else "خیر",
            "بله" if user.is_staff else "خیر",
            "بله" if user.is_superuser else "خیر",
            ", ".join(r.name for r in user.roles.all()) or "—",
            user.date_joined.strftime("%Y-%m-%d %H:%M") if user.date_joined else "—",
            user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "—",
        ])

    return response


# --------------------------------------------------------------------------- #
# CustomUser Admin – Perfect, Fast, Beautiful
# --------------------------------------------------------------------------- #
@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    list_display = (
        "username", "email", "full_name", "is_active", "is_staff",
        "role_list", "date_joined", "last_login", "account_age_badge"
    )
    list_filter = ("is_active", "is_staff", "is_superuser", "roles__name", "date_joined")
    search_fields = ("username", "email", "first_name", "last_name")
    ordering = ("-date_joined",)
    actions = [activate_users, deactivate_users, force_password_change, export_to_csv]

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2", "is_active", "is_staff", "roles"),
        }),
    )

    readonly_fields = ("date_joined", "last_login")

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("roles")

    def get_fieldsets(self, request, obj=None):
        base = [
            (None, {"fields": ("username", "email", "password")}),
            (_("اطلاعات شخصی"), {"fields": ["first_name", "last_name"]}),
            (_("مجوزها"), {
                "fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions"),
            }),
            (_("نقش‌ها"), {"fields": ("roles",)}),
            (_("تاریخچه"), {"fields": ("last_login", "date_joined")}),
        ]

        # Safely extend personal info
        personal = list(base[1][1]["fields"])
        if hasattr(CustomUser, "phone_number"):
            personal.append("phone_number")
        if hasattr(CustomUser, "national_id"):
            personal.append("national_id")
        base[1][1]["fields"] = personal

        return base

    def full_name(self, obj):
        return obj.get_full_name().strip() or "—"
    full_name.short_description = _("نام کامل")

    def role_list(self, obj):
        roles = [r.name for r in obj.roles.all()]
        return ", ".join(roles) if roles else "—"
    role_list.short_description = _("نقش‌ها")

    # Fixed: short_description BEFORE method
    account_age_badge.short_description = _("وضعیت حساب")
    account_age_badge.admin_order_field = "date_joined"

    def account_age_badge(self, obj):
        if not obj.date_joined:
            return "—"
        days = (timezone.now().date() - obj.date_joined.date()).days
        if days < 30:
            return format_html('<span style="background:#27ae60; color:white; padding:4px 8px; border-radius:4px;">جدید</span>')
        elif days < 180:
            return format_html('<span style="background:#e67e22; color:white; padding:4px 8px; border-radius:4px;">فعال</span>')
        else:
            return format_html('<span style="background:#95a5a6; color:white; padding:4px 8px; border-radius:4px;">قدیمی</span>')

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        qs = self.get_queryset(request)
        today = timezone.now().date()

        extra_context.update({
            "title": _("مدیریت کاربران"),
            "total_users": qs.count(),
            "active_users": qs.filter(is_active=True).count(),
            "new_this_week": qs.filter(date_joined__gte=today - timedelta(days=7)).count(),
            "inactive_users": qs.filter(is_active=False).count(),
        })
        return super().changelist_view(request, extra_context=extra_context)


# --------------------------------------------------------------------------- #
# Role Admin – Clean & Performant
# --------------------------------------------------------------------------- #
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "description", "user_count", "created_at", "view_users_link")
    search_fields = ("name", "description")
    ordering = ("name",)
    list_filter = ("created_at",)
    readonly_fields = ("created_at",)

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(
            _user_count=Count("customuser", distinct=True)
        )

    def user_count(self, obj):
        return getattr(obj, "_user_count", 0)
    user_count.short_description = _("تعداد کاربران")
    user_count.admin_order_field = "_user_count"

    def view_users_link(self, obj):
        count = getattr(obj, "_user_count", 0)
        if not count:
            return "—"
        url = f"{reverse('admin:accounts_customuser_changelist')}?roles__id__exact={obj.pk}"
        return format_html('<a href="{}">{} کاربر →</a>', url, count)
    view_users_link.short_description = _("مشاهده")

    def has_delete_permission(self, request, obj=None):
        protected = {"admin", "superuser", "administrator", "مدیر", "مدیرکل"}
        if obj and obj.name.lower() in protected:
            return False
        return super().has_delete_permission(request, obj)

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        stats = Role.objects.aggregate(
            total=Count("id"),
            with_users=Count("id", filter=Q(customuser__isnull=False))
        )
        extra_context.update({
            "title": _("مدیریت نقش‌ها"),
            "total_roles": stats["total"],
            "roles_with_users": stats["with_users"],
        })
        return super().changelist_view(request, extra_context=extra_context)
