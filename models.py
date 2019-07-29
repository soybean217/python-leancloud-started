
from flask_login import UserMixin
import leancloud

class User(UserMixin):
    pass


def query_user(login_name):
    ManagerUser = leancloud.Object.extend('ManagerUser')
    query = ManagerUser.query
    query.equal_to('login_name', login_name)
    #query.equal_to('password', password)
    try:
        mUser = query.first()
    except LeanCloudError as e:
        mUser = None
        flash('login fail')
    return mUser
