import os
from dotenv import load_dotenv
from django.shortcuts import render, redirect
import requests
from django.contrib.auth import login, logout
from django.contrib.auth.models import User

load_dotenv()

AIESEC_AUTH_URL = "https://auth.aiesec.org/oauth/authorize"
AIESEC_TOKEN_URL = "https://auth.aiesec.org/oauth/token"
AIESEC_USER_URL = "https://gis-api.aiesec.org/v2/me.json"

CLIENT_ID = os.getenv("AIESEC_CLIENT_ID")
CLIENT_SECRET = os.getenv("AIESEC_CLIENT_SECRET")
REDIRECT_URI = os.getenv("AIESEC_REDIRECT_URI")

def login_page(request):
    """Renders the login page"""
    return render(request, "login_page.html")

def aiesec_login(request):
    """Redirects user to AIESEC OAuth login"""
    auth_url = f"{AIESEC_AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    return redirect(auth_url)

def aiesec_callback(request):
    """Handles OAuth callback and logs the user in"""
    code = request.GET.get("code")
    if not code:
        return redirect("/")  # Redirect to login page if no code

    # Exchange authorization code for access token
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        # "grant_type": "authorization_code",
        "code": code,
    }

    response = requests.post(AIESEC_TOKEN_URL, data=data)
    token_data = response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        return redirect("/")  # Redirect if authentication fails

    # Fetch user data from AIESEC
    headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get(AIESEC_USER_URL, headers=headers)
    user_data = user_response.json()

    # Extract user details
    email = user_data.get("email")
    first_name = user_data.get("first_name")
    last_name = user_data.get("last_name")

    if not email:
        return redirect("/")  # Redirect if no email found

    # Create or update user in Django's auth system
    user, created = User.objects.get_or_create(username=email, defaults={
        "first_name": first_name,
        "last_name": last_name,
        "email": email
    })

    # Log in the user
    login(request, user)

    # Store access token in session
    request.session["access_token"] = access_token

    return redirect("/home/")  # Redirect to home page

def home(request):
    """Simple home page after login"""
    user = request.user
    if user.is_authenticated:
        return render(request, "home.html", {"user": user})
    return redirect("/")

def logout_view(request):
    """Logs the user out"""
    logout(request)
    request.session.flush()
    return redirect("/")
