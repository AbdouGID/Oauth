from django.urls import path
from .views import aiesec_login, aiesec_callback

urlpatterns = [
    path("oauth/aiesec/", aiesec_login, name="aiesec-login"),
    path("oauth/callback/", aiesec_callback, name="aiesec-callback"),
]
