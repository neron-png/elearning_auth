import json
from pprint import pprint
import secrets
from bs4 import BeautifulSoup
import pkce
import requests
import urllib.parse




def generate_token(username: str, password: str) -> dict:
    state: str = secrets.token_hex(nbytes=8)
    code_verifier: str = pkce.generate_code_verifier(length=128)
    code_challenge: str = pkce.get_code_challenge(code_verifier)
    
    # cookiejar.CookieJar() #TODO
    session = requests.Session()
    
    # Step 1: Initial GET request
    initial_url = "https://elearning.auth.gr/auth/saml/index.php?wantsurl=https://elearning.auth.gr/"

    
    response = session.get(url=initial_url)
    resp_url = response.url
    auth_state = resp_url.split("?AuthState=")[1]
    post_url = resp_url.split("?AuthState=")[0]
    
    
    # step 2
    form_data = {
        "username": username,
        "password": password,
        "AuthState": urllib.parse.unquote(auth_state),
    }

    resp2 = session.post(post_url, data=form_data)
    
    # print(resp2.text)
    soup2 = BeautifulSoup(resp2.text, "html.parser")
    form2_url = soup2.find("form")["action"]
    saml_response = soup2.find("input", {"name": "SAMLResponse"})["value"]
    relay_state = soup2.find("input", {"name": "RelayState"})["value"]

    
    # step 3
    form3_data = {
        "SAMLResponse": saml_response,
        "RelayState": relay_state
    }
    
    resp3 = session.post(form2_url, data=form3_data)
    
    soup3 = BeautifulSoup(resp3.text, "html.parser")
    sesskey = None
    scripts = soup3.find_all("script")
    for script in scripts:
        if "M.cfg" in script.text:
            # extract the contents of M.cfg within the text
            # and split them into a list
            cfg = json.loads(script.text.split("M.cfg = ")[1].split(";")[0])
            sesskey = cfg["sesskey"]
            break
    # print(session.cookies)
    # save the Moodle session cookie from session.cookies
    # to a variable called moodle_session
    moodle_session = session.cookies.get("MoodleSession")
    print("MoodleSession=", moodle_session)
    print("sesskey=", sesskey)

if __name__ == "__main__":
    generate_token(username="", password="")