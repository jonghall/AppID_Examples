#!/usr/bin/env python
# Example of registering user in Cloud Directory using IBM Cloud AppID
# https://us-south.appid.cloud.ibm.com/swagger-ui/#/

import json, os, requests, urllib, string, secrets

def getiamtoken(apikey):
    ################################################
    ## Lookup interface by ID
    ################################################

    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/json"}

    parms = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": apikey}

    try:
        resp = requests.post("https://iam.cloud.ibm.com/identity/token?"+urllib.parse.urlencode(parms), headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
            print("Invalid token request.")
            print("template=%s" % parms)
            print("Error Data:  %s" % errb)
            print("Other Data:  %s" % resp.text)
            quit()


    iam = resp.json()

    iamtoken = {"Authorization": "Bearer " + iam["access_token"]}

    return iamtoken

def random_string(size):
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(letters) for i in range(size))

def signupUser(userinfo):
    try:
        resp = requests.post(appidEndpoint + '/management/v4/' + appidTennantId + '/cloud_directory/sign_up?shouldCreateProfile=true', json=userinfo, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        print ("Unknown Error", errb)
        print (resp)
        quit()

    if resp.status_code == 201:
        user = json.loads(resp.content)

    else:
        print("Unknown Error", resp)
        quit()

    return user

def updateProfile(id, attributes):
    try:
        resp = requests.put(appidEndpoint + '/management/v4/' + appidTennantId + '/users/' + id + '/profile', json=attributes, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        print ("Unknown Error", errb)
        print (resp)
        quit()

    if resp.status_code == 200:
        profile = json.loads(resp.content)

    else:
        print("Unknown Error", resp)
        quit()

    return profile


if __name__ == '__main__':
    appidEndpoint = "https://us-east.appid.cloud.ibm.com"
    apikey = os.getenv("IC_API_KEY")
    headers = getiamtoken(apikey)
    appidTennantId = "658b2ef3-275b-4ed9-be65-defc85368b0a"

    firstName = input("First Name: ")
    lastName = input("Last Name: ")
    email = input("Email: ")
    print ("Creating user account in Cloud Directory...")

    userName = random_string(20)
    password = random_string(20)

    newUser = {
          "active": True,
          "emails": [
            {
              "value": email,
              "primary": True
            }
          ],
            "name": {
                "familyName": lastName,
                "givenName": firstName,
            },
          "userName": userName,
          "password": password
            }

    user = signupUser(newUser)

    attributes = {"attributes": {"access-groups": "poc-admin"}}
    profile = updateProfile(user["profileId"], attributes)

    print ("Created user and profile in Cloud Directory for %s (pw=%s)" % (firstName, password))
    print ()
    print (json.dumps(profile, indent=4))
