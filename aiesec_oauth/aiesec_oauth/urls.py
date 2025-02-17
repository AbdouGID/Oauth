"""
URL configuration for aiesec_oauth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import render, redirect
from django.http import HttpResponse
from authapp.views import aiesec_login, aiesec_callback, filter_view, fetch_filtered_results

def home(request):
    return render(request, "home.html")

urlpatterns = [
    path('admin/', admin.site.urls),
    path("accounts/", include("allauth.urls")),
    path('', home, name='home'),
    path("auth/", include("authapp.urls")),  # Custom OAuth
    path("filters/", filter_view, name="filters"),
    path("fetch-results/", fetch_filtered_results, name="fetch_filtered_results"),
]

