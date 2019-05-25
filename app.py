from flask import Flask,request,redirect,url_for
from forms import LoginForm
from flask import render_template
from flask_wtf.csrf import CsrfProtect
from models import User
from flask_login import login_user, login_required
from flask_login import LoginManager, current_user
from flask_login import logout_user
import os
from functools import wraps

app = Flask(__name__)

app.secret_key = os.urandom(24)

# use login manager to manage session
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app=app)
groupchoose=0
# 这个callback函数用于reload User object，根据session中存储的user id
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# csrf protection
csrf = CsrfProtect()
csrf.init_app(app)


@app.route('/login',methods={'POST','GET'})
def login():
    form = LoginForm()
#    if form.validate_on_submit():
    user_name = request.form.get('username', None)
    print(user_name)
    password = request.form.get('password', None)
    print(password)
    remember_me = request.form.get('remember_me', False)
    print(remember_me)
    user = User(user_name)
    if user.verify_password(password):
        login_user(user, remember=remember_me)
        return redirect(request.args.get('next') or url_for('main'))
    return render_template('login.html', title="Sign In", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
#@login_required
def index():
    #username=User.get_username()
    diaries=[{'time': '2019-05-23, 7:30pm',
                'content': '喵喵喵'}]
    return render_template('index.html', name="Alice",diaries=diaries)

@app.route('/showgroups')
def showgroups():
    #select group info and how many people alive in last 5 mins to be a param
    return render_template('showgroups.html')

def groupchoose_required(func):
    @wraps(func)
    def wapper(*args, **kwargs):
        groupchoose = request.args.get('groupchoose')
        groupchoose=-1
        if groupchoose !=-1:
            return func(groupchoose)
        else:
            return redirect(url_for('showgroups'))
    return wapper

@app.route('/chat')
@groupchoose_required
def chat(groupchoose):
    msgs = [
            {
                'mem': '小爱同学',
                'time': '2019-05-23, 7:30pm',
                'msg': '你好，我是小爱同学'
            },
            {
                'mem': '天猫精灵',
                'time': '2019-05-23, 7:40pm',
                'msg': '你好，我是天猫精灵'
            },
            {
                'mem': '小爱同学',
                'time':'2019-05-23, 8:00pm',
                'msg': '天猫精灵，唱拔萝卜'
            }
        ]
    return render_template('chat.html',name=groupchoose,msgs=msgs)


if __name__ == '__main__':
    app.run()
