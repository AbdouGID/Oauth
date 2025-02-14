import os
from dotenv import load_dotenv
from django.shortcuts import render, redirect
import requests
from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.models import User

load_dotenv()

AIESEC_AUTH_URL = "https://auth.aiesec.org/oauth/authorize"
AIESEC_TOKEN_URL = "https://auth.aiesec.org/oauth/token"
AIESEC_USER_URL = "https://gis-api.aiesec.org/graphql"

CLIENT_ID = os.getenv("AIESEC_CLIENT_ID")
CLIENT_SECRET = os.getenv("AIESEC_CLIENT_SECRET")
REDIRECT_URI = os.getenv("AIESEC_REDIRECT_URI")


def login_page(request):
    """Redirect authenticated users to /auth/, otherwise show login page."""
    if request.user.is_authenticated:
        return redirect("/auth/")
    return render(request, "welcome.html")


def aiesec_login(request):
    """Redirect user to AIESEC OAuth login"""
    auth_url = f"{AIESEC_AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code" # issue in code? 
    return redirect(auth_url)

def fetch_user_data(request, force_refresh=False):
    """Fetch user data from AIESEC GraphQL API"""
    access_token = request.session.get("access_token")

    print(f"Using Access Token: {access_token}")

    graphql_query = {
        "query": """
        {
            currentPerson {
                full_name
                email
            }
        }
        """
    }

    headers = {
        "Authorization": access_token,
        "Content-Type": "application/json"
    }

    user_response = requests.post(AIESEC_USER_URL, json=graphql_query, headers=headers)

    print("User API Response Status Code:", user_response.status_code)
    print("Raw User Response:", user_response.text)

    if user_response.status_code == 401:  # Still invalid after refresh
        print("Still getting invalid token after refresh. Logging out.")
        return logout_and_redirect(request)

    try:
        user_data = user_response.json().get("data", {}).get("currentPerson", {})
    except requests.exceptions.JSONDecodeError:
        print("JSONDecodeError: Invalid JSON response from AIESEC user API")
        return None

    if not user_data or "email" not in user_data:
        print("No email found in user data. Logging out.")
        return logout_and_redirect(request)

    return user_data

def aiesec_callback(request):
    """Handles OAuth callback and logs the user in"""
    code = request.GET.get("code")
    if not code:
        print("Error: No authorization code received")
        return redirect("/")

    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
    }

    response = requests.post(AIESEC_TOKEN_URL, data=token_data, headers={"Accept": "application/json"})
    print("Raw Token Response:", response.text)

    try:
        token_data = response.json()
    except requests.exceptions.JSONDecodeError:
        print("JSONDecodeError: Invalid JSON response from AIESEC token API")
        return redirect("/")

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        print("Error: No access token received. Full response:", token_data)
        return redirect("/")

    request.session["access_token"] = access_token
    request.session["refresh_token"] = refresh_token
    request.session.modified = True  

    user_data = fetch_user_data(request)

    if user_data is None:
        print("Failed to retrieve user data. Logging out.")
        return logout_and_redirect(request)

    email = user_data.get("email")
    full_name = user_data.get("full_name", "")

    first_name, *last_name = full_name.split(" ", 1)
    last_name = last_name[0] if last_name else ""

    if not email:
        print("Error: No email found in user data")
        return logout_and_redirect(request)

    User = get_user_model()  # Ensure the correct user model is used
    user, created = User.objects.get_or_create(username=email, defaults={
        "first_name": first_name,
        "last_name": last_name,
        "email": email
    })

    # Explicitly set authentication backend to avoid AttributeError
    user.backend = 'django.contrib.auth.backends.ModelBackend'
    
    login(request, user)
    print(f"User {user.username} logged in successfully")

    return render(request, "dashboard.html", {"user": request.user})

def logout_and_redirect(request):
    """Logs out user and redirects to login page"""
    logout(request)
    request.session.flush()
    return redirect("/")

def home(request):
    """Redirect authenticated users to a dashboard page instead of looping to /auth/"""
    if request.user.is_authenticated:
        return render(request, "dashboard.html", {"user": request.user})
    return render(request, "home.html", {"user": None})


def logout_view(request):
    """Logs the user out"""
    return logout_and_redirect(request)
