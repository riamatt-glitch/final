from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

admin.site.site_header = 'RBVMS Administration'
admin.site.site_title = 'RBVMS'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='vulnmgmt/login.html',
                                                redirect_authenticated_user=True), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('password/', auth_views.PasswordChangeView.as_view(
        template_name='vulnmgmt/form.html', success_url='/',
        extra_context={'title': 'Change password'}), name='password_change'),
    path('', include('vulnmgmt.urls')),
]
