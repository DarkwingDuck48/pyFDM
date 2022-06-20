from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """login action"""
    if request.method == 'POST':
        email:str = request.form.get('email')
        password:str = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.homepage'))
            flash('Incorrect password, try again!', category='error')
        else:
            flash("Email does not exist! Sign in or correct email", category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    """logout action"""
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route('/sign-up',  methods=['GET', 'POST'])
def sign_up():
    """sign_up action"""
    if request.method == 'POST':
        email:str = request.form.get('email')
        first_name:str = request.form.get('firstName')
        password1:str = request.form.get('password1')
        password2:str = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already exist!', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 chars', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 char', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters', category='error')
        else:
            #add user
            pass_hash = generate_password_hash(password1, method='sha256')
            new_user = User(email=email, first_name=first_name, password=pass_hash)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created', category='sucsess')
            return redirect(url_for('views.homepage'))

    return render_template("sign_up.html", user=current_user)
