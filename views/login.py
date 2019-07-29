# coding: utf-8
import leancloud
from leancloud import Object
from leancloud import Query
from leancloud import LeanCloudError
from flask import Blueprint
from flask import request
from flask import redirect
from flask import url_for
from flask import render_template


class Todo(Object):
    pass

login_view = Blueprint('login', __name__)


@login_view.route('')
def show():
    return render_template('login.html')


@login_view.route('', methods=['POST'])
def login():
    login_name = request.form['login_name']
    password = request.form['password']
    ManagerUser = leancloud.Object.extend('ManagerUser')
    query = ManagerUser.query
    query.equal_to('login_name', login_name)
    query.equal_to('password', password)
    mUser = query.first()
    try:
        if mUser != None :
            return redirect(url_for('users.show'))
        else :
            return render_template('login.html',msg="login fail") 
    except LeanCloudError as e:
        #return e.error, 502
        return render_template('login.html',msg="login fail") 
    return redirect(url_for('login.show'))
