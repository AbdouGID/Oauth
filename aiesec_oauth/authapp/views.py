import os
from dotenv import load_dotenv
from django.shortcuts import render, redirect
import requests
from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.models import User
from django.http import JsonResponse
import traceback

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

def refresh_access_token(request):
    """Refresh AIESEC OAuth token"""
    refresh_token = request.session.get("refresh_token")

    if not refresh_token:
        print("❌ No refresh token found. Logging out.")
        return None  # Return None if no refresh token

    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    response = requests.post(AIESEC_TOKEN_URL, data=token_data, headers={"Accept": "application/json"})
    print("🔄 Refresh Token Response:", response.text)

    if response.status_code == 200:
        try:
            new_token_data = response.json()
            new_access_token = new_token_data.get("access_token")
            new_refresh_token = new_token_data.get("refresh_token")

            if new_access_token:
                request.session["access_token"] = new_access_token
                request.session["refresh_token"] = new_refresh_token
                request.session.modified = True
                print("✅ Token refreshed successfully.")
                return new_access_token
        except Exception as e:
            print(f"⚠️ Error parsing refresh response: {e}")

    print("❌ Token refresh failed.")
    return None  # Return None if refresh fails

def get_filters(request):
    """Retrieve filter values dynamically from AIESEC API"""
    api_url = "https://gis-api.aiesec.org/graphql"
    graphql_query = {
        "query": """
        {
            allOpportunity {
                data {
                    host_lc { 
                        name 
                    }
                    backgrounds { 
                        constant_name 
                    }
                    skills { 
                        constant_name 
                    }
                    programme { 
                        short_name 
                    }
                }
            }
        }
        """
    }

    access_token = request.session.get("access_token")

    if not access_token:
        print("No access token found. Refreshing...")
        access_token = refresh_access_token(request)

    if not access_token:
        print("🚨 Token refresh failed. Logging out user.")
        return redirect("/auth/logout/")

    headers = {
        "Authorization": access_token,
        "Content-Type": "application/json"
    }

    response = requests.post(api_url, json=graphql_query, headers=headers)
    
    print("API Access token:", access_token)
    print("API Response Status:", response.status_code)
    print("API Response Data:", response.text)

    if response.status_code == 401:
        print("🔄 Token expired! Refreshing token...")
        access_token = refresh_access_token(request)

        if not access_token:
            print("🚨 Token refresh failed. Logging out user.")
            return redirect("/auth/logout/")

        headers["Authorization"] = f"Bearer {access_token}"
        response = requests.post(api_url, json=graphql_query, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json().get("data", {}).get("allOpportunity", {}).get("data", [])
            print("Parsed Data:", data)

            host_regions = sorted(set([opp["host_lc"]["name"] for opp in data if opp.get("host_lc")]))
            backgrounds = sorted(set([bg["constant_name"] for opp in data if opp.get("backgrounds") for bg in opp["backgrounds"]]))
            skills = sorted(set([sk["constant_name"] for opp in data if opp.get("skills") for sk in opp["skills"]]))
            product_types = sorted(set([opp["programme"]["short_name"] for opp in data if opp.get("programme")]))

            return {
                "host_regions": host_regions,
                "backgrounds": backgrounds,
                "skills": skills,
                "product_types": product_types
            }
        except Exception as e:
            print(f"Error processing API response: {e}")
            return {"host_regions": [], "backgrounds": [], "skills": [], "product_types": []}

    print("API request failed, returning empty filters.")
    return {"host_regions": [], "backgrounds": [], "skills": [], "product_types": []}

def filter_opportunities(request):
    """Render the filter page with dynamic values"""
    filters = get_filters(request)
    return render(request, "filter_page.html", {"filters": filters})

def fetch_filtered_opportunities(request):
    """Handle AJAX request and return filtered opportunities"""
    if request.method == "POST":
        try:
            print("🔄 Received POST Data:", request.POST)

            selected_filters = request.POST.getlist("filters[]")
            print("🔍 Selected Filters Extracted:", selected_filters)

            api_url = "https://gis-api.aiesec.org/graphql"
            graphql_query = {
                "query": """
                {
                    allOpportunity {
                        data {
                            host_lc { name }
                            backgrounds { constant_name }
                            skills { constant_name }
                            programme { short_name }
                        }
                    }
                }
                """
            }

            access_token = request.session.get("access_token")

            if not access_token:
                print("No access token found. User might be logged out.")
                return JsonResponse({"error": "Authentication required"}, status=401)

            headers = {
                "Authorization": access_token,
                "Content-Type": "application/json"
            }

            response = requests.post(api_url, json=graphql_query, headers=headers)

            if response.status_code != 200:
                print(f"API request failed with status {response.status_code}")
                return JsonResponse({"error": "Failed to fetch opportunities"}, status=500)

            data = response.json().get("data", {}).get("allOpportunity", {}).get("data", [])

            print("Parsed Data Before Filtering:", data)

            def matches_filter(opp):
                try:
                    return (
                        opp.get("host_lc", {}).get("name") in selected_filters or
                        any(bg.get("constant_name") in selected_filters for bg in opp.get("backgrounds", [])) or
                        any(sk.get("constant_name") in selected_filters for sk in opp.get("skills", [])) or
                        opp.get("programme", {}).get("short_name") in selected_filters
                    )
                except Exception as e:
                    print(f"Error in filtering logic: {e}")
                    return False

            filtered_opportunities = [opp for opp in data if matches_filter(opp)]

            print("Filtered Opportunities:", filtered_opportunities)

            response_data = {
                "message": "Filters applied successfully!",
                "filters": selected_filters,
                "opportunities": filtered_opportunities
            }

            return JsonResponse(response_data)

        except Exception as e:
            print("An error occurred in fetch_filtered_opportunities:", str(e))
            print(traceback.format_exc())
            return JsonResponse({"error": "Internal server error"}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)
