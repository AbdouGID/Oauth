from django.shortcuts import render
import requests
from django.shortcuts import redirect
from django.conf import settings

AIESEC_AUTH_URL = "https://auth.aiesec.org/oauth/authorize"
AIESEC_TOKEN_URL = "https://auth.aiesec.org/oauth/token"
AIESEC_USER_URL = "https://gis-api.aiesec.org/v2/me.json"

CLIENT_ID = "t5faSjuv2EJ1EgT5DQlFxGvADXCg-UIdln0yvN9dRA4"
CLIENT_SECRET = "je1SgDV1dEBVO3DCfoHth9qb_7rSq9w9m7wCCWvMaiI"
REDIRECT_URI = "https://expa.aiesec.org"

def aiesec_login(request):
    auth_url = f"{AIESEC_AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    return redirect(auth_url)

def aiesec_callback(request):
    code = request.GET.get("code")
    if not code:
        return redirect("/")  # Redirect to home if authentication fails

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        #"grant_type": "authorization_code",
        "code": code,
    }

    response = requests.post(AIESEC_TOKEN_URL, data=data)
    token_data = response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        return redirect("/")  # Redirect if authentication fails

    headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get(AIESEC_USER_URL, headers=headers)
    user_data = user_response.json()

    print(user_data)

    return redirect("/")

from django.contrib.auth import logout

def logout_view(request):
    """Logs the user out and clears the session."""
    logout(request)
    request.session.flush()
    return redirect("/")
