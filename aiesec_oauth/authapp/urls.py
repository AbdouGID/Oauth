from django.urls import path
from .views import aiesec_login, aiesec_callback, login_page, home, logout_view

urlpatterns = [
    path("", login_page, name="login"),
    path("oauth/aiesec/", aiesec_login, name="aiesec-login"),
    path("oauth/callback/", aiesec_callback, name="aiesec-callback"),
    path("home/", home, name="home"),
    path("logout/", logout_view, name="logout"),
]
