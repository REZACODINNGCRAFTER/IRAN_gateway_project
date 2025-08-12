from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib import messages
from django.utils.timezone import now
import csv
import datetime

from .models import CustomUser, Role


@admin.action(description='Activate selected users')
def activate_users(modeladmin, request, queryset):
    updated = queryset.update(is_active=True)
    messages.success(request, _(f"{updated} users activated."))


@admin.action(description='Deactivate selected users')
def deactivate_users(modeladmin, request, queryset):
    updated = queryset.update(is_active=False)
    messages.warning(request, _(f"{updated} users deactivated."))


@admin.action(description='Reset password to default for selected users')
def reset_passwords(modeladmin, request, queryset):
    for user in queryset:
        user.set_password('DefaultPassword123')
        user.save()
    messages.info(request, _(f"{queryset.count()} passwords reset."))


@admin.action(description='Export selected users to CSV')
def export_to_csv(modeladmin, request, queryset):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=users_export.csv'
    writer = csv.writer(response)

    writer.writerow(['Username', 'Email', 'Active', 'Staff', 'Roles'])
    for user in queryset:
        writer.writerow([
            user.username,
            user.email,
            user.is_active,
            user.is_staff,
            ", ".join([r.name for r in user.roles.all()])
        ])
    return response


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    list_display = (
        'username', 'email', 'is_active', 'is_staff', 'role_list',
        'last_login', 'date_joined', 'days_since_joined', 'view_profile_link', 'account_age_category'
    )
    search_fields = ('username', 'email')
    list_filter = ('is_active', 'is_staff', 'roles')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined', 'last_login')
    actions = [activate_users, deactivate_users, reset_passwords, export_to_csv]

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        (_('Roles & Status'), {'fields': ('roles',)}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'is_active', 'is_staff', 'roles'),
        }),
    )

    def role_list(self, obj):
        return ", ".join(role.name for role in obj.roles.all())
    role_list.short_description = 'Roles'

    def view_profile_link(self, obj):
        return format_html('<a class="button" href="/admin/accounts/customuser/{}/change/">Edit</a>', obj.pk)
    view_profile_link.short_description = 'Edit'
    view_profile_link.allow_tags = True

    def days_since_joined(self, obj):
        return (now().date() - obj.date_joined.date()).days
    days_since_joined.short_description = 'Days Since Joined'

    def account_age_category(self, obj):
        days = (now().date() - obj.date_joined.date()).days
        if days < 30:
            return 'New'
        elif days < 180:
            return 'Active'
        else:
            return 'Established'
    account_age_category.short_description = 'Account Age'

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = _('Manage Custom Users')
        extra_context['user_count'] = CustomUser.objects.count()
        extra_context['active_users'] = CustomUser.objects.filter(is_active=True).count()
        extra_context['recent_joins'] = CustomUser.objects.filter(date_joined__gte=now().date()).count()
        return super().changelist_view(request, extra_context=extra_context)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'created_at', 'user_count', 'view_users_link')
    search_fields = ('name', 'description')
    ordering = ('name', 'created_at')
    list_filter = ('created_at',)

    def user_count(self, obj):
        return obj.customuser_set.count()
    user_count.short_description = 'Assigned Users'

    def view_users_link(self, obj):
        url = reverse('admin:accounts_customuser_changelist') + f'?roles__id__exact={obj.id}'
        return format_html('<a href="{}">View Users</a>', url)
    view_users_link.short_description = 'Users'

    def has_delete_permission(self, request, obj=None):
        if obj and obj.name.lower() in ['admin', 'superuser']:
            return False
        return super().has_delete_permission(request, obj)

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = _('Manage User Roles')
        extra_context['total_roles'] = Role.objects.count()
        extra_context['non_empty_roles'] = Role.objects.exclude(customuser=None).count()
        return super().changelist_view(request, extra_context=extra_context)
