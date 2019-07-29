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
            return redirect(url_for('index'))
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


@app.route('/users')
@login_required
def users():
    return app.send_static_file('html/users.html')


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
                '_User')).descending('updatedAt').limit(1000).find()
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
            mobilePhoneNumber = request.get_json()['mobilePhoneNumber']
        except KeyError:
            raise BadRequest(
                '''receives malformed POST content (proper schema: '{"content": "TODO CONTENT"}')''') 
        if len(objectId)>0:
            #leancloud.init("JdgetNRNLj7wvSs7wYs1hlNF-gzGzoHsz", master_key="bnPlVUIFezts6FwXmFPF0iHk")
            User = leancloud.Object.extend('_User')
            query = User.query
            user = query.get(objectId)
        else :
            user = leancloud.Object.extend('_User')()
            user.set('password','password')
        user.set('username',username)
        user.set('mobilePhoneNumber',mobilePhoneNumber)
        try:
            user.save()
        except LeanCloudError as e:
            raise BadGateway(e.error, e.code)
        else:
            return jsonify(success=True)
