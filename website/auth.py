from flask import Blueprint, render_template, render_template_string, request, flash, redirect, url_for
from .models import User, Note
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.sql import select, update


auth = Blueprint('auth', __name__)


@auth.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='plain'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)


@auth.route('/lookup/', methods=['GET', 'POST'])
@login_required
def lookup():  
    if request.method == 'POST':
        userId = request.form.get('userId')
        query = "SELECT * FROM Note WHERE user_Id='" + userId + "'"
        result = db.engine.execute(query)
        rows = result.fetchall()
        return render_template("lookup.html", user=current_user, rows=rows, userId=userId)
        
    return render_template("lookup.html", user=current_user)

@auth.route('/support/', methods=['GET', 'POST'])
@login_required
def support():  
    if request.method == 'POST':
        ticket = request.form.get('ticket')
        query = "<h1>Your support ticket has been submitted</h1><br>"+ ticket
        return render_template_string(query, user=current_user)
        #test = "<h3>Notes for User ID </h3>"+ userId
        #return render_template_string(test, user=current_user, rows=rows, userId=userId)
        
    return render_template("support.html", user=current_user)

@auth.route('/setting/', methods=['GET', 'POST'])
@login_required
def setting():  
    if request.method == 'POST':
        pass1 = request.form.get('pass1')
        pass2 = request.form.get('pass2')

        if pass1 == pass2:

            newPassword = generate_password_hash(pass1, method='plain')
            updatePassword = (
                update(User).
                where(User.id == current_user.id).
                values(password=newPassword)
            )
            result = db.engine.execute(updatePassword)
            flash('Your password has been updated!', category='success')

        else:
            flash('Passwords don\'t match.', category='error')

    return render_template("setting.html", user=current_user)
