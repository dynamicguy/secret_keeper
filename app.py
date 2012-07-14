from flask.helpers import flash
import os
from flask import Flask, url_for, redirect, render_template, request
from flask.ext.sqlalchemy import SQLAlchemy
from platform import system
from flask.ext.restless import APIManager
from flask.ext.admin.contrib.sqlamodel import filters
from flask.ext import admin, login, wtf
from flask.ext.admin.contrib.sqlamodel import ModelView
from flask.ext.wtf import (Form, TextField, TextAreaField, PasswordField,
                           SubmitField, Required, ValidationError)
from werkzeug import check_password_hash, generate_password_hash
from hashlib import md5
from datetime import datetime


# Create application

app = Flask(__name__)

def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' %\
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

app.jinja_env.filters['gravatar'] = gravatar_url

# Create dummy secrey key so we can use sessions
app.config['SECRET_KEY'] = '1f2f3f456790'

# Create in-memory database
#dbname=d9fsb63lvi7t81 host=ec2-23-23-237-0.compute-1.amazonaws.com port=5432 user=oteqvtwvsdsbwg password=joqwk_RXjraBB91B1D16_H8h2L sslmode=require
if "Darwin" == system():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://keeper:please@localhost/secret-keeper'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://oteqvtwvsdsbwg:joqwk_RXjraBB91B1D16_H8h2L@ec2-23-23-237-0.compute-1.amazonaws.com/d9fsb63lvi7t81'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


# Create user model. For simplicity, it will store passwords in plain text.
# Obviously that's not right thing to do in real world application.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120))
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.login

post_tags_table = db.Table('post_tags', db.Model.metadata,
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime)

    user_id = db.Column(db.Integer(), db.ForeignKey(User.id))
    user = db.relationship(User, backref='posts')

    tags = db.relationship('Tag', secondary=post_tags_table)

    def __unicode__(self):
        return self.title


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64), nullable=False)

    def __unicode__(self):
        return self.name

# Define login and registration forms (for flask-login)
class LoginForm(Form):
    login = TextField(validators=[Required()])
    password = PasswordField(validators=[Required()])

    def validate_login(self, field):
        user = self.get_user()
        if user is None:
            raise ValidationError, 'Invalid user'

    def validate_password(self, field):
        user = self.get_user()
        if not user.check_password(self.password.data):
            raise ValidationError, 'Invalid password'

    def get_user(self):
        return db.session.query(User).filter_by(login=self.login.data).first()


class RegistrationForm(Form):
    login = TextField(validators=[Required()])
    email = TextField()
    password = PasswordField(validators=[Required()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(login=self.login.data).count() > 0:
            raise ValidationError, 'Duplicate username'


# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.setup_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)


# Create customized model view class
class UserModelView(ModelView):
    def is_accessible(self):
        return login.current_user.is_authenticated()

    list_columns = ('login', 'email')
    searchable_columns = ('login', 'email')
    column_filters = ('login', 'email')

class PostModelView(ModelView):
    def is_accessible(self):
        return login.current_user.is_authenticated()

    # Visible columns in the list view
    list_columns = ('title', 'user')
    excluded_list_columns = ['text']

    # List of columns that can be sorted. For 'user' column, use User.username as
    # a column.
    sortable_columns = ('title', ('user', User.login), 'date')

    # Rename 'title' columns to 'Post Title' in list view
    rename_columns = dict(title='Post Title')

    searchable_columns = ('title', User.login)

    column_filters = ('user',
                      'title',
                      'date',
                      filters.FilterLike(Post.title, 'Fixed Title', options=(('test1', 'Test 1'), ('test2', 'Test 2'))))

    # Pass arguments to WTForms. In this case, change label for text field to
    # be 'Big Text' and add required() validator.
    form_args = dict(
        text=dict(label='Big Text', validators=[wtf.required()])
    )

# Create customized index view class
class KeeperAdminIndexView(admin.AdminIndexView):
    def is_accessible(self):
        return login.current_user.is_authenticated()



# Flask views
@app.route('/')
def index():
    return render_template('index.html', user=login.current_user)


@app.route('/login/', methods=('GET', 'POST'))
def login_view():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = form.get_user()
        login.login_user(user)
        flash('You were logged in')
        return redirect(url_for('index'))

    return render_template('login.html', form=form)


@app.route('/register/', methods=('GET', 'POST'))
def register_view():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        user = User(form.login.data, request.form['password'])
        form.populate_obj(user)
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        login.login_user(user)
        return redirect(url_for('index'))

    return render_template('form.html', form=form)


@app.route('/logout/')
def logout_view():
    login.logout_user()
    """Logs the user out."""
    flash('You were logged out')
    return redirect(url_for('index'))

@app.route('/posts/')
def posts_view():
    posts = Post.query.all()
    return render_template('posts.html', posts=posts, user=login.current_user)

if __name__ == '__main__':
    # Initialize flask-login
    init_login()

    # Create admin
    admin = admin.Admin(app, 'Secret keeper admin panel', index_view=KeeperAdminIndexView())
    admin.add_view(PostModelView(Post, db.session, url='posts'))
    admin.add_view(ModelView(Tag, db.session, url='tags'))
    admin.add_view(UserModelView(User, db.session, url='users'))

    # Create DB
    db.create_all()

    manager = APIManager(app, flask_sqlalchemy_db=db)
    manager.create_api(User, methods=['GET', 'POST', 'DELETE'])
    manager.create_api(Post, methods=['GET', 'POST', 'DELETE'])
    manager.create_api(Tag, methods=['GET', 'POST', 'DELETE'])
    # Start app
    app.debug = True
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
