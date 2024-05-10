from flask import Flask, render_template, redirect, session, request, flash
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.exceptions import Unauthorized

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'verysecretkey'

connect_db(app)

db.create_all()

toolbar = DebugToolbarExtension(app)

@app.route('/')
def homepage():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            password=User.hash_password(form.password.data),
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(user)
        db.session.commit()
        session['username'] = user.username
        return redirect('/users/<username>')

    return render_template('user_register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            session['username'] = user.username
            return redirect('/users/<username>')
        flash('Invalid username or password')

    return render_template('user_login.html', form=form)

@app.route('/logout')
def logout_user():
    session.pop('username')
    return redirect('/')

@app.route('/users/<username>')
def show_user(username):
    if 'username' not in session or username != session['username']:
        flash('You are not authorized to view this page.')
        return redirect('/')
    user = User.query.get_or_404(username)
    return render_template('show_user.html', user=user)

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' not in session or username != session['username']:
        flash('You are not authorized to perform this action.')
        return redirect('/')
    form = FeedbackForm()

    if form.validate_on_submit():
        feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=username
        )
    return render_template('new_feedback.html', form=form)