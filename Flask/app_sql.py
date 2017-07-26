"""Flask Login Example and instagram fallowing find"""

import sys
import os
import random
import struct
import hashlib
import pickle
import time
import sqlite3
import string
import getpass
import csv
import numpy as np
from flask import Flask, url_for, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy

user_database_location = './bin/user_creds.db'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)


class User(db.Model):
    """ Create user table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))

    def __init__(self, username, password):
        self.username = username
        self.password = password


def fetchUserInfo(file_name, user):
    db = sqlite3.connect(file_name)
    cursor = db.cursor()
    cursor.execute(
        '''SELECT user, pwd_sha512, pwdChanged, email FROM users WHERE user=?''', (user,))
    userinfo_ = cursor.fetchone()
    db.close()
    return userinfo_


def addUser(file_name, admin, auto=False, user=None, email=None):
    user_ = user
    email_ = email
    userinfo_ = fetchUserInfo(file_name, user_)
    if userinfo_ is None:
        # generate random password
        PWD_new_ = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
        PWD_new_sha512_ = hashlib.sha512(PWD_new_.encode('utf8')).hexdigest()
        db = sqlite3.connect(file_name)
        cursor = db.cursor()
        cursor.execute('''INSERT INTO users(user, pwd_sha512, pwdChanged, email)
                          VALUES(?,?,?,?)''', (user_, PWD_new_sha512_, 0, email_))
        db.commit()
        db.close()
    else:
        return "User \"" + str(user_) + "\"  already exits."
    return user_ + '     ' + email_ + '     Temporary password: ' + PWD_new_

# changing password for users
def changePassword(file_name, user, pwd1, pwd2, pwd_old=None, first_time=False):
    userinfo_ = fetchUserInfo(file_name, user)
    if first_time:
        PWD_old_sha512 = hashlib.sha512(pwd_old.encode('utf8')).hexdigest()
        if userinfo_[1] != PWD_old_sha512:
            return 1
    if pwd1 != pwd2:
        return 2
        PWD_new_sha512_ = hashlib.sha512(
            pwd1.encode('utf8')).hexdigest()
    if PWD_new_sha512_ != userinfo_[1]:
        db = sqlite3.connect(file_name)
        cursor = db.cursor()
        cursor.execute('''UPDATE users SET pwd_sha512 = ? WHERE user = ? ''',
                       (PWD_new_sha512_, user))
        cursor.execute('''UPDATE users SET pwdChanged = ? WHERE user = ? ''',
                        (1, user))
        db.commit()
        db.close()
        return 0
    else:
        return 3


def getUserInfo(file_name):
    user_dict_ = {}
    user_dict = {}
    db = sqlite3.connect(file_name)
    cursor = db.cursor()
    cursor.execute('''SELECT user, email FROM users''')
    for row in cursor:
        user_dict_[row[0]] = row[1]
    return user_dict_



@app.route('/', methods=['GET', 'POST'])
def home():
    """ Session control"""
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        if request.method == 'POST':
            username = getname(request.form['username'])
            return render_template('index.html', data=username)
        return render_template('index.html')

@app.route('/createPoll', methods=['GET', 'POST'])
def createPoll():
    """ creating new polls """
    if not session.get('logged_in'):
        return render_template('index.html')
    elif not session.get('admin'):
        return render_template('poll_index.html')

    if request.method == 'GET':
        return render_template('create_poll.html')
        pollName_ = request.form['pollName']
    return render_template('create_poll.html')


@app.route('/poll_index', methods=['GET', 'POST'])
def poll_index():
    """ access after login """
    if not session.get('logged_in'):
        return render_template('index.html')
    elif session.get('admin'):
        return render_template('poll_index_admin.html')
    else:
        #if request.method == 'POST':
        #    username = getname(request.form['username'])
        #    return render_template('poll_index.html', data=username)
        return render_template('poll_index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Form"""
    errors = []
    session['logged_in'] = False
    session['admin'] = False
    session['user'] = False
    if request.method == 'GET':
        return render_template('login.html', errors=errors)
    else:
        name = request.form['username']
        passw = request.form['password']
        passw_sha512_ = hashlib.sha512(
                        passw.encode('utf8')).hexdigest()
        userinfo_ = fetchUserInfo(user_database_location, name)
        if userinfo_ != None:
            if passw_sha512_ == userinfo_[1]:
                session['logged_in'] = True
                if name == 'admin':
                    session['admin'] = True
                else:
                    session['user'] = True
                return redirect(url_for('poll_index'))
        errors.append("Username or password is incorrect. Try again!")
    return render_template('login.html', errors=errors)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    """Register Form"""
    errors = []
    msg0 = []
    if request.method == 'POST':
        name_ = request.form['name']
        username_ = request.form['username']
        email_ = request.form['email']
        msg = addUser(user_database_location, admin=True, auto=True, user=username_, email=email_)
        msg0.append(msg)
        return render_template('register.html', msg0=msg0)
    return render_template('register.html', errors=errors)

@app.route('/manager/', methods=['GET', 'POST'])
def manager():
    errors = []
    if request.method == 'POST':
        print(request.form.get('delete_user'))
    elif request.method == 'GET':
        userInfo_ = getUserInfo(user_database_location)
    return render_template('manager.html', errors=errors, result=userInfo_)


@app.route("/logout")
def logout():
    """Logout Form"""
    session['logged_in'] = False
    session['admin'] = False
    session['user'] = False
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.debug = True
    db.create_all()
    app.secret_key = "123"
    app.run(host='0.0.0.0')
    
