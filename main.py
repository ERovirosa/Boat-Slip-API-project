from google.cloud import datastore
from requests_oauthlib import OAuth2Session
from flask import Flask, request, Response, make_response
import json
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests
import constants

# This disables the requirement to use HTTPS so that you can test locally.
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

client = datastore.Client()

# These should be copied from an OAuth2 Credential section at
# https://console.cloud.google.com/apis/credentials
client_id = r'497969534781-cv8e7irbuq45kujknri9kid3tpp6aoaa.apps.googleusercontent.com'
client_secret = r'sIrx2qNqMC8IVFSGL7VOhEFP'

# This is the page that you will use to decode and collect the info from
# the Google authentication flow
redirect_uri = 'http://127.0.0.1:8080/oauth'
# These let us get basic info to identify a user and not much else
# they are part of the Google People API
scope = [
    "openid", 'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

# This link will redirect users to begin the OAuth flow with Google


@app.route('/welcome')
def index():
    authorization_url, state = oauth.authorization_url(
        'https://accounts.google.com/o/oauth2/auth',
        # access_type and prompt are Google specific extra
        # parameters.
        access_type="offline",
        prompt="select_account")
    return 'Welcome<br> Please go <a href=%s>here</a> to log in or create a new account.' % authorization_url


# This is where users will be redirected back to and where you can collect
# the JWT for use in future requests


@app.route('/oauth')
def oauthroute():
    token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token',
                              authorization_response=request.url,
                              client_secret=client_secret)
    req = requests.Request()

    id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)

    entity = datastore.entity.Entity(
        key=client.key(constants.users, id_info['sub']))
    entity.update({"Email": id_info["email"]})
    client.put(entity)

    print(id_info)
    return "Your JWT is: %s <br> <br> <br> Your unique ID is: %s" % (
        token['id_token'], id_info['sub'])


# This page demonstrates verifying a JWT. id_info['email'] contains
# the user's email address and can be used to identify them
# this is the code that could prefix any API call that needs to be
# tied to a specific user by checking that the email in the verified
# JWT matches the email associated to the resource being accessed.


@app.route('/verify-jwt1')
def verify():
    req = requests.Request()

    id_info = id_token.verify_oauth2_token(request.args['jwt'], req, client_id)

    return repr(id_info) + "<br><br> the user is: " + id_info['email']


@app.route('/verify-jwt2')
def verify2():
    req = requests.Request()
    #print(request.headers.get("authorization"))
    bearerToken = request.headers.get("authorization").split(' ')
    id_info = id_token.verify_oauth2_token(bearerToken[1], req, client_id)

    return repr(id_info) + "<br><br> the user is: " + id_info['email']


@app.route('/users', methods=['GET'])
def GET_USERS():
    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            print(e)
            e["id"] = e.key.name
        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(results))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        else:
            response = {
                "Error":
                "This function only supports responding with json data"
            }
            return json.dumps(response), 406
    else:
        response = {"Error": "Method not allowed"}
        return json.dumps(response), 405


@app.route('/boats', methods=['POST', 'GET'])
def boat_post():
    if request.method == 'POST':
        try:
            req = requests.Request()
            bearerToken = request.headers.get("authorization").split(' ')
            id_info = id_token.verify_oauth2_token(bearerToken[1], req,
                                                   client_id)
        except:
            response = {"Error": "Missing or invalid JWT"}
            return json.dumps(response), 401

        content = request.get_json()
        try:
            boat = {
                "name": content["name"],
                "type": content["type"],
                "length": content["length"],
                "owner": id_info['sub']
            }
        except KeyError:
            response = {
                "Error":
                "The request object is missing at least one of the required attributes"
            }
            return json.dumps(response), 400

        entity = datastore.entity.Entity(key=client.key(constants.boats))
        entity.update(boat)
        client.put(entity)

        entity["id"] = entity.key.id
        entity["self"] = request.url_root + \
            constants.boats + "/" + str(entity.key.id)

        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(entity))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 201
            return res
        else:
            response = {
                "Error":
                "This function only supports responding with json data"
            }
            return json.dumps(response), 406
    if request.method == 'GET':
        try:
            req = requests.Request()
            bearerToken = request.headers.get("authorization").split(' ')
            id_info = id_token.verify_oauth2_token(bearerToken[1], req,
                                                   client_id)
        except:
            response = {"Error": "Missing or invalid JWT"}
            return json.dumps(response), 401

        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
        owned = []
        for ent in results:
            if id_info['sub'] == ent["owner"]:
                owned.append(ent)

        total = len(owned)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        page = []
        for e in range(q_limit):
            if q_offset + e < len(owned):
                page.append(owned[q_offset + e])
        if q_offset + 5 < len(owned):
            next_offset = q_offset + 5
            next_url = request.base_url + "?limit=" + \
            str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        # print(output)
        for e in page:
            e["id"] = e.key.id
            e["self"] = request.url_root + \
            constants.boats + "/" + str(e.key.id)
        output = {"boats": page}
        if next_url:
            output["next"] = next_url
        output["total"] = total

        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(output))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        else:
            response = {
                "Error":
                "This function only supports responding with json data"
            }
            return json.dumps(response), 406
    else:
        response = {"Error": "Method not allowed"}
        return json.dumps(response), 405


@app.route('/boats/<id>', methods=['GET', 'PATCH', 'DELETE'])
def single_boat(id):
    try:
        req = requests.Request()
        bearerToken = request.headers.get("authorization").split(' ')
        id_info = id_token.verify_oauth2_token(bearerToken[1], req, client_id)
    except:
        response = {"Error": "Missing or invalid JWT"}
        return json.dumps(response), 401

    key = client.key(constants.boats, int(id))
    entity = client.get(key)
    if (not entity) or (id_info['sub'] != entity["owner"]):
        response = {
            "Error":
            "The user with this jwt does not own a boat with this boat ID"
        }
        return json.dumps(response), 403
    if request.method == 'PATCH':
        content = request.get_json()
        try:
            entity["name"] = content["name"]
            entity["type"] = content["type"]
            entity["length"] = content["length"]
        except KeyError:
            response = {
                "Error":
                "The request object is missing at least one of the required attributes"
            }
            return json.dumps(response), 400
        client.put(entity)
    elif request.method == 'DELETE':
        if entity["current_slip"]:
            slip = client.get(
                client.key(constants.slips, entity["current_slip"]))
            slip["current_boat"] = None
            client.put(slip)
        client.delete(key)
        return "", 204
    entity["id"] = entity.key.id
    entity["self"] = request.url_root + \
        constants.boats + "/" + str(entity.key.id)
    if 'application/json' in request.accept_mimetypes:
        res = make_response(json.dumps(entity))
        res.headers.set('Content-Type', 'application/json')
        if request.method == 'PATCH':
            res.status_code = 201
        else:
            res.status_code = 200
        return res
    else:
        response = {
            "Error": "This function only supports responding with json data"
        }
        return json.dumps(response), 406


@app.route('/slips', methods=['POST', 'GET'])
def create_slip():
    if request.method == 'POST':
        content = request.get_json()
        try:
            slip = {
                "number": content["number"],
                "length": content["length"],
                "width": content["width"]
            }
        except KeyError:
            response = {
                "Error":
                "The request object is missing at least one of the required attributes"
            }
            return json.dumps(response), 400

        entity = datastore.entity.Entity(key=client.key(constants.slips))
        entity.update(slip)
        client.put(entity)
        entity_id = str(entity.key.id)
        # print(request)
        entity["id"] = entity.key.id
        entity["current_boat"] = None
        entity["self"] = request.url_root + \
            constants.slips + "/" + str(entity.key.id)
        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(entity))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 201
            return res
        else:
            response = {
                "Error":
                "This function only supports responding with json data"
            }
            return json.dumps(response), 406
    elif request.method == 'GET':
        query = client.query(kind=constants.slips)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            if not "current_boat" in e:
                e["current_boat"] = None

        total = len(results)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        page = []
        for e in range(q_limit):
            if q_offset + e < len(results):
                page.append(results[q_offset + e])
        if q_offset + 5 < len(results):
            next_offset = q_offset + 5
            next_url = request.base_url + "?limit=" + \
            str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in page:
            e["id"] = e.key.id

        output = {"boats": page}
        if next_url:
            output["next"] = next_url
        output["total"] = total

        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(output))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        else:
            response = {
                "Error":
                "This function only supports responding with json data"
            }
            return json.dumps(response), 406
    else:
        response = {"Error": "Method not allowed"}
        return json.dumps(response), 405


@app.route('/slips/<id>', methods=['GET', 'DELETE'])
def get_slip(id):
    key = client.key(constants.slips, int(id))
    entity = client.get(key)
    if not entity:
        response = {"Error": "No slip with this slip_id exists"}
        return json.dumps(response), 404

    if request.method == 'DELETE':
        client.delete(key)
        return "", 204

    entity["id"] = entity.key.id
    entity["self"] = request.url_root + \
        constants.slips + "/" + str(entity.key.id)
    if not "current_boat" in entity:
        entity["current_boat"] = None
    if 'application/json' in request.accept_mimetypes:
        res = make_response(json.dumps(entity))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    else:
        response = {
            "Error": "This function only supports responding with json data"
        }
        return json.dumps(response), 406


@app.route('/slips/<slip_id>/<boat_id>', methods=['PUT', 'DELETE'])
def boat_into_slip(slip_id, boat_id):
    key = client.key(constants.slips, int(slip_id))
    slip = client.get(key)
    key = client.key(constants.boats, int(boat_id))
    boat = client.get(key)

    if not slip or not boat:
        if request.method == 'PUT':
            response = {"Error": "The specified boat and/or slip don’t exist"}
        else:
            response = {
                "Error":
                "No boat with this boat_id is at the slip with this slip_id"
            }
        return json.dumps(response), 404
    if request.method == 'PUT':
        if "current_boat" in slip and slip["current_boat"]:
            response = {"Error": "The slip is not empty"}
            return json.dumps(response), 403
        slip["current_boat"] = int(boat_id)
        boat["current_slip"] = int(slip_id)
    elif request.method == 'DELETE':
        if slip["current_boat"] != int(boat_id):
            response = {
                "Error":
                "No boat with this boat_id is at the slip with this slip_id"
            }
            return json.dumps(response), 404
        slip["current_boat"] = None
        boat["current_slip"] = None
    else:
        response = {"Error": "Method not allowed"}
        return json.dumps(response), 405
    client.put(slip)
    client.put(boat)
    return "", 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
