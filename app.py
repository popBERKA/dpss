from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from config import Config
from models import db, User, SupportRequest, Comment
from forms import RegisterForm, LoginForm, UpdateProfileForm, CreateRequestForm, CommentForm

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            full_name=form.full_name.data,
            phone_number=form.phone_number.data,
            email=form.email.data,
            office_number=form.office_number.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.full_name = form.full_name.data
        current_user.phone_number = form.phone_number.data
        current_user.email = form.email.data
        current_user.office_number = form.office_number.data
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)

@app.route('/create_request', methods=['GET', 'POST'])
@login_required
def create_request():
    form = CreateRequestForm()
    if form.validate_on_submit():
        support_request = SupportRequest(
            user_id=current_user.id,
            full_name=current_user.full_name,
            phone_number=current_user.phone_number,
            email=current_user.email,
            office_number=current_user.office_number,
            subject=form.subject.data,
            message=form.message.data,
            status='Awaiting response'
        )
        db.session.add(support_request)
        db.session.commit()
        flash('Support request created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('create_request.html', form=form)

@app.route('/view_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def view_request(request_id):
    support_request = SupportRequest.query.get_or_404(request_id)
    form = CommentForm()
    if form.validate_on_submit() and support_request.status != 'Completed':
        comment = Comment(
            support_request_id=request_id,
            user_id=current_user.id,
            content=form.content.data
        )
        db.session.add(comment)
        if support_request.status == 'Awaiting response' and current_user.username == 'Admin':
            support_request.status = 'In Progress'
        db.session.commit()
        flash('Comment added successfully!', 'success')
        return redirect(url_for('view_request', request_id=request_id))
    comments = Comment.query.filter_by(support_request_id=request_id).order_by(Comment.timestamp.asc()).all()
    return render_template('view_request.html', support_request=support_request, form=form, comments=comments)

@app.route('/close_request/<int:request_id>', methods=['POST'])
@login_required
def close_request(request_id):
    support_request = SupportRequest.query.get_or_404(request_id)
    if support_request.user_id == current_user.id or current_user.username == 'Admin':
        support_request.status = 'Completed'
        db.session.commit()
        flash('Request closed successfully!', 'success')
    else:
        flash('You do not have permission to perform this action', 'danger')
    return redirect(url_for('view_request', request_id=request_id))

@app.route('/user_requests')
@login_required
def user_requests():
    user_requests = SupportRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('user_requests.html', requests=user_requests)

@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.username != 'Admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    support_requests = SupportRequest.query.all()
    return render_template('admin_panel.html', support_requests=support_requests)

@app.route('/active_chats')
@login_required
def active_chats():
    if current_user.username != 'Admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    active_requests = SupportRequest.query.filter(SupportRequest.status == 'Awaiting response').all()
    return render_template('active_chats.html', active_requests=active_requests)

if __name__ == "__main__":
    app.run(debug=True)