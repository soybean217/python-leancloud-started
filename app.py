# coding: utf-8
import sys
from datetime import datetime

import leancloud
#leancloud.init("JdgetNRNLj7wvSs7wYs1hlNF-gzGzoHsz", master_key="bnPlVUIFezts6FwXmFPF0iHk")
from flask import Flask, jsonify, request, flash, url_for, redirect
from flask import render_template
from flask_sockets import Sockets
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from leancloud import LeanCloudError
from models import User, query_user

from views.todos import todos_view
#from views.login import login_view
from views.users import users_view

app = Flask(__name__)
app.secret_key = '1234567'
sockets = Sockets(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = '请登录'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(login_name):
    if query_user(login_name) is not None:
        curr_user = User()
        curr_user.id = login_name
        return curr_user


# 动态路由
app.register_blueprint(todos_view, url_prefix='/todos')
#app.register_blueprint(login_view, url_prefix='/login')
#app.register_blueprint(users_view, url_prefix='/users')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #user_id = request.form.get('userid')
        login_name = request.form.get('login_name')
        password = request.form.get('password')
        user = query_user(login_name)
        # if user is not None and request.form['password'] == user['password']:
        if user is not None and request.form.get('password') == user.get('password'):
            print('in2c')
            curr_user = User()
            curr_user.id = login_name

            # 通过Flask-Login的login_user方法登录用户
            login_user(curr_user)
            return redirect(url_for('users'))
        flash('Wrong username or password!')

    # GET 请求
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!')
    return render_template('login.html')


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/time')
def time():
    return str(datetime.now())


@app.route('/version')
def print_version():
    import sys
    return sys.version


@sockets.route('/echo')
def echo_socket(ws):
    while True:
        message = ws.receive()
        ws.send(message)


# REST API example
class BadGateway(Exception):
    status_code = 502

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_json(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return jsonify(rv)


class BadRequest(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_json(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return jsonify(rv)


@app.errorhandler(BadGateway)
def handle_bad_gateway(error):
    response = error.to_json()
    response.status_code = error.status_code
    return response


@app.errorhandler(BadRequest)
def handle_bad_request(error):
    response = error.to_json()
    response.status_code = error.status_code
    return response


@app.route('/api/python-version', methods=['GET'])
def python_version():
    return jsonify({"python-version": sys.version})


@app.route('/api/todos', methods=['GET', 'POST'])
def todos():
    if request.method == 'GET':
        try:
            todo_list = leancloud.Query(leancloud.Object.extend(
                'Todo')).descending('createdAt').find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([todo.dump() for todo in todo_list])
    elif request.method == 'POST':
        try:
            content = request.get_json()['content']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content (proper schema: '{"content": "TODO CONTENT"}')''')
        todo = leancloud.Object.extend('Todo')()
        todo.set('content', content)
        try:
            todo.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)


@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def apiUsers():
    if request.method == 'GET':
        try:
            user_list = leancloud.Query(leancloud.Object.extend(
                '_User')).include('Role').descending('updatedAt').limit(1000).find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([user.dump() for user in user_list])
    elif request.method == 'POST':
        try:
            #content = request.get_json()['content']
            print(request.get_json())
            objectId = request.get_json()['objectId']
            username = request.get_json()['username']
            roleList = request.get_json()['roleList']
            mobilePhoneNumber = request.get_json()['mobilePhoneNumber']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content (proper schema: '{"content": "TODO CONTENT"}')''')
        if len(objectId) > 0:
            #leancloud.init("JdgetNRNLj7wvSs7wYs1hlNF-gzGzoHsz", master_key="bnPlVUIFezts6FwXmFPF0iHk")
            User = leancloud.Object.extend('_User')
            query = User.query
            user = query.get(objectId)
        else:
            user = leancloud.Object.extend('_User')()
            user.set('password', 'password')
        user.set('username', username)
        user.set('mobilePhoneNumber', mobilePhoneNumber)
        try:
            user.save()
            role_query = leancloud.Query(leancloud.Role)
            role_query_list = role_query.find()
            for role in role_query_list:
                print(role.dump())
                if role.get('name') in roleList :
                    relation = role.get_users()
                    relation.add(user)
                    role.save()
                else:
                    role_query.equal_to('users', user)
                    role_query_with_current_user = role_query.find()
                    if len(role_query_with_current_user) > 0:
                        relation = role.get_users()
                        relation.remove(user)
                        role.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)

@app.route('/api/roles', methods=['GET', 'POST'])
@login_required
def apiRoles():
    if request.method == 'GET':
        try:
            role_query = leancloud.Query(leancloud.Role)
            role_query_list = role_query.find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([item.dump() for item in role_query_list])
    elif request.method == 'POST':
        return jsonify(success=True)

@app.route('/api/userRoles', methods=['GET', 'POST'])
@login_required
def apiUserRoles():
    if request.method == 'GET':
        try:
            userObjectId = request.args.get('userObjectId')
            User = leancloud.Object.extend('_User')
            query = User.query
            user = query.get(userObjectId)
            role_query = leancloud.Query(leancloud.Role)
            role_query.equal_to('users', user)
            role_query_list = role_query.find() 
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([item.dump() for item in role_query_list])
    elif request.method == 'POST':
        return jsonify(success=True)


@app.route('/api/groups', methods=['GET', 'POST'])
@login_required
def apiGroups():
    if request.method == 'GET':
        try:
            result_list = leancloud.Query(leancloud.Object.extend(
                'Group')).descending('updatedAt').limit(1000).find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([item.dump() for item in result_list])
    elif request.method == 'POST':
        try:
            #content = request.get_json()['content']
            print(request.get_json())
            objectId = request.get_json()['objectId']
            name = request.get_json()['name']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content ''')
        if len(objectId) > 0:
            #leancloud.init("JdgetNRNLj7wvSs7wYs1hlNF-gzGzoHsz", master_key="bnPlVUIFezts6FwXmFPF0iHk")
            Item = leancloud.Object.extend('Group')
            query = Item.query
            item = query.get(objectId)
        else:
            item = leancloud.Object.extend('Group')()
        item.set('name', name)
        try:
            item.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)


@app.route('/api/endpoints', methods=['GET', 'POST'])
@login_required
def endpoints():
    if request.method == 'GET':
        try:
            group = request.args.get('group')
            if group  and len(group) > 0 and group!='null':
                print(group)
                Obj = leancloud.Object.extend('Group')
                query = Obj.query
                item = query.get(group)
                #result_list = leancloud.Object.extend('Endpoint').query.equal_to('group', item).add_ascending('updatedAt').find()
                result_list = leancloud.Query(leancloud.Object.extend(
                    'Endpoint')).include('group').equal_to('group', item).descending('updatedAt').limit(1000).find()
            else:
                result_list = leancloud.Query(leancloud.Object.extend(
                    'Endpoint')).include('group').descending('updatedAt').limit(1000).find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([item.dump() for item in result_list])
    elif request.method == 'POST':
        try:
            #content = request.get_json()['content']
            print(request.get_json())
            objectId = request.get_json()['objectId']
            name = request.get_json()['name']
            location = request.get_json()['location']
            groupObjectId = request.get_json()['group']['objectId']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content ''')
        if len(objectId) > 0:
            #leancloud.init("JdgetNRNLj7wvSs7wYs1hlNF-gzGzoHsz", master_key="bnPlVUIFezts6FwXmFPF0iHk")
            Item = leancloud.Object.extend('Endpoint')
            query = Item.query
            item = query.get(objectId)
        else:
            item = leancloud.Object.extend('Endpoint')()
        if len(groupObjectId)>0 :
            Obj = leancloud.Object.extend('Group')
            query = Obj.query
            group = query.get(groupObjectId)
            item.set('group',group)
        item.set('name', name)
        item.set('location', location)
        try:
            item.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)

@app.route('/api/userEndpoints', methods=['GET', 'POST'])
@login_required
def apiUserEndpoints():
    if request.method == 'GET':
        try:
            endpointObjectId = request.args.get('endpoint')
            Obj = leancloud.Object.extend('Endpoint')
            query = Obj.query
            endpoint = query.get(endpointObjectId)

            user_query = leancloud.User.query

            which_in_endpoint = leancloud.Object.extend('UserEndpoint').query.include('user').equal_to('endpoint', endpoint)
            #user_query = user_query.and_(user_query, leancloud.User.query.matches_key_in_query('objectId', 'user.objectId', which_in_endpoint))
            #user_query =  leancloud.User.query.matches_key_in_query('objectId', 'user.objectId', which_in_endpoint)
            #user_query =  leancloud.User.query.contains_all('objectId', 'user.objectId', which_in_endpoint)
            
            user_list = which_in_endpoint.find()
        except LeanCloudError as e:
            if e.code == 101:  # 服务端对应的 Class 还没创建
                return jsonify([])
            else:
                raise BadGateway(e.error, e.code)
        else:
            return jsonify([{
                'username':user.get('user',{}).get('username'),
                'mobilePhoneNumber':user.get('user',{}).get('mobilePhoneNumber'),
                'objectId':user.get('objectId'),} for user in user_list])
    elif request.method == 'POST':
        try:
            #content = request.get_json()['content']
            print(request.get_json())
            userObjectId = request.get_json()['userObjectId']
            endpointObjectId = request.get_json()['endpointObjectId']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content (proper schema: '{"content": "TODO CONTENT"}')''')
        User = leancloud.Object.extend('_User')
        query = User.query
        user = query.get(userObjectId)
        endpoint = leancloud.Object.extend('Endpoint').query.get(endpointObjectId)
        userEndpoint = leancloud.Object.extend('UserEndpoint')()
        userEndpoint.set('user',user)
        userEndpoint.set('endpoint',endpoint)
        try:
            userEndpoint.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)

@app.route('/api/userEndpoints/delete', methods=['GET', 'POST'])
@login_required
def apiUserEndpointsDelete():
    if request.method == 'GET':
        return 
    elif request.method == 'POST':
        try:
            #content = request.get_json()['content']
            print(request.get_json())
            objectId = request.get_json()['objectId']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content (proper schema: '{"content": "TODO CONTENT"}')''')
        item = leancloud.Object.extend('UserEndpoint').query.get(objectId)
        try:
            item.destroy()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)



@app.route('/users')
@login_required
def users():
    return app.send_static_file('html/users.html')


@app.route('/groups')
@login_required
def groups():
    return app.send_static_file('html/groups.html')

@app.route('/endpoints')
@login_required
def endPoints():
    return app.send_static_file('html/endpoints.html')

@app.route('/userEndpoints')
@login_required
def userEndPoints():
    return app.send_static_file('html/userEndpoints.html')

