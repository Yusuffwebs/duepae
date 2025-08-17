from datetime import datetime
import datetime as dt
import pdfkit
import os
from xhtml2pdf import pisa
from io import BytesIO
import uuid
from functools import wraps
from flask import make_response, render_template_string
import tempfile
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import or_, func
import pytz
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rent.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['APP_TIMEZONE'] = 'Asia/Kolkata'
db = SQLAlchemy(app)

# Admin configuration
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "123"
ADMIN_PHONE = "0000000000"  # Use a constant for admin phone


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def validate_csrf_token(token):
    return token == session.get('csrf_token')


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    upi_id = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    subscription_end = db.Column(db.Date, nullable=True)
    whatsapp_enabled = db.Column(db.Boolean, default=True)

    owned_properties = relationship("Property", back_populates="owner")
    tenancies_as_tenant = relationship("Tenancy", foreign_keys="Tenancy.tenant_id", back_populates="tenant")
    tenancies_as_owner = relationship("Tenancy", foreign_keys="Tenancy.owner_id", back_populates="owner_user")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")

    def set_password(self, password):
        """Set password (admin can use this without knowing current password)"""
        self.password_hash = generate_password_hash(password)
        return True

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def has_active_subscription(self):
        if self.role == 'admin':
            return True
        return self.subscription_end and self.subscription_end >= dt.date.today()

    @property
    def is_unregistered(self):
        return self.username.startswith('unregistered_')


class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = relationship("User", back_populates="owned_properties")
    tenancies = relationship("Tenancy", back_populates="property")


class Tenancy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    rent_amount = db.Column(db.Numeric(10, 2), nullable=False)
    due_date = db.Column(db.Date, nullable=False)

    owner_user = relationship("User", foreign_keys=[owner_id], back_populates="tenancies_as_owner")
    tenant = relationship("User", foreign_keys=[tenant_id], back_populates="tenancies_as_tenant")
    property = relationship("Property", back_populates="tenancies")
    payments = relationship("Payment", back_populates="tenancy")


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenancy_id = db.Column(db.Integer, db.ForeignKey('tenancy.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    payment_date = db.Column(db.Date, default=dt.date.today)
    status = db.Column(db.String(20), default='pending')
    upi_txn_id = db.Column(db.String(120))
    notes = db.Column(db.String(255))
    receipt_generated = db.Column(db.Boolean, default=False)

    tenancy = relationship("Tenancy", back_populates="payments")


class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    require_subscription = db.Column(db.Boolean, default=False)
    subscription_price = db.Column(db.Numeric(10, 2), default=500.00)
    subscription_duration = db.Column(db.Integer, default=30)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    message_type = db.Column(db.String(20), default='notification')

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")


# Helper Functions
def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def send_whatsapp_message(phone, message):
    print(f"Sending WhatsApp to {phone}: {message}")
    return True


def create_message(sender_id, receiver_id, content, message_type='notification'):
    message = Message(
        sender_id=sender_id,
        receiver_id=receiver_id,
        content=content,
        message_type=message_type
    )
    db.session.add(message)
    db.session.commit()

    receiver = User.query.get(receiver_id)
    if receiver and receiver.whatsapp_enabled:
        send_whatsapp_message(receiver.phone, content)

    return message

def serialize_sqla_obj(obj):
    """Serializes a SQLAlchemy object to a dictionary, handling dates and relationships."""
    if not obj:
        return None
    data = {}
    mapper = db.inspect(obj.__class__)
    for column in mapper.columns:
        value = getattr(obj, column.key)
        if isinstance(value, dt.date):
            data[column.key] = value.isoformat()
        elif isinstance(value, dt.datetime):
            data[column.key] = value.isoformat()
        else:
            data[column.key] = value
    return data


@app.before_request
def load_user():
    g.user = current_user()

    if g.user and g.user.role != 'admin':
        config = SystemConfig.query.first()
        if config and config.require_subscription and not g.user.has_active_subscription:
            flash("Your subscription has expired. Please renew to continue using our services.", "warning")


@app.context_processor
def inject_user():
    config = SystemConfig.query.first() or SystemConfig()
    unread_count = 0
    current_user_obj = current_user()
    if current_user_obj:
        unread_count = db.session.query(Message).filter_by(
            receiver_id=current_user_obj.id,
            is_read=False
        ).count()

    def to_local_time(utc_dt):
        if not utc_dt:
            return ""
        tz = pytz.timezone(app.config['APP_TIMEZONE'])
        return utc_dt.replace(tzinfo=pytz.utc).astimezone(tz)

    return dict(
        user=current_user_obj,
        current_user=current_user_obj,
        datetime=dt.datetime,
        config=config,
        unread_count=unread_count,
        to_local_time=to_local_time
    )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated


def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.role != 'owner':
            abort(403)
        return f(*args, **kwargs)

    return decorated


def tenant_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.role != 'tenant':
            abort(403)
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)

    return decorated


def subscription_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        config = SystemConfig.query.first()

        if not user or user.role == 'admin':
            return f(*args, **kwargs)

        if config and config.require_subscription and not user.has_active_subscription:
            flash("You need an active subscription to access this feature", "danger")
            return redirect(url_for('subscription'))

        return f(*args, **kwargs)

    return decorated


# Initialize Database and Admin User
def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()

        # Create system config if not exists
        config = SystemConfig.query.first()
        if not config:
            config = SystemConfig()
            db.session.add(config)
            db.session.commit()

        # Check if admin user exists by username
        admin = User.query.filter_by(username=ADMIN_USERNAME).first()

        if admin:
            # Admin exists, update if needed
            if not admin.check_password(ADMIN_PASSWORD):
                admin.set_password(ADMIN_PASSWORD)
                print("Admin password updated", file=sys.stderr)
            if admin.phone != ADMIN_PHONE:
                # Handle phone conflict
                existing_phone_user = User.query.filter_by(phone=ADMIN_PHONE).first()
                if existing_phone_user and existing_phone_user.id != admin.id:
                    # Resolve conflict by deleting the conflicting user
                    db.session.delete(existing_phone_user)
                    print(f"Deleted conflicting user with phone: {ADMIN_PHONE}", file=sys.stderr)
                admin.phone = ADMIN_PHONE
            db.session.commit()
            return

        # Check if admin phone exists
        existing_phone_user = User.query.filter_by(phone=ADMIN_PHONE).first()

        if existing_phone_user:
            # Convert existing user to admin
            existing_phone_user.role = 'admin'
            existing_phone_user.username = ADMIN_USERNAME
            existing_phone_user.full_name = "Admin User"
            existing_phone_user.set_password(ADMIN_PASSWORD)
            existing_phone_user.is_active = True
            print("Converted existing user to admin", file=sys.stderr)
        else:
            # Create new admin user
            admin = User(
                role='admin',
                username=ADMIN_USERNAME,
                full_name="Admin User",
                phone=ADMIN_PHONE,
                is_active=True,
                whatsapp_enabled=True
            )
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
            print("Created new admin user", file=sys.stderr)

        db.session.commit()


# Auth Routes
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user():
        if current_user().role == 'owner':
            return redirect(url_for('owner_dashboard'))
        elif current_user().role == 'tenant':
            return redirect(url_for('tenant_dashboard'))
        elif current_user().role == 'admin':
            return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Login attempt - Username: {username}, Password: {password}")

        user = User.query.filter_by(username=username).first()
        print(f"User found: {user}")

        if user:
            print(f"Password check: {user.check_password(password)}")
            print(f"User active: {user.is_active}")

        if user and user.check_password(password) and user.is_active:
            session['user_id'] = user.id
            print(f"Login successful, user ID: {user.id}")
            flash("Login successful!", "success")

            if user.role == 'tenant':
                tenancies = Tenancy.query.filter_by(tenant_id=user.id).all()
                today = dt.date.today()
                for tenancy in tenancies:
                    last_payment = Payment.query.filter_by(
                        tenancy_id=tenancy.id
                    ).order_by(Payment.payment_date.desc()).first()

                    if not last_payment or last_payment.payment_date < tenancy.due_date:
                        if tenancy.due_date < today:
                            content = f"⚠️ Rent Overdue! {tenancy.property.name} rent was due on {tenancy.due_date.strftime('%Y-%m-%d')}"
                            create_message(
                                sender_id=tenancy.owner_id,
                                receiver_id=user.id,
                                content=content,
                                message_type='warning'
                            )

            if user.role == 'owner':
                return redirect(url_for('owner_dashboard'))
            elif user.role == 'tenant':
                return redirect(url_for('tenant_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials or account disabled", "danger")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    phone = request.args.get('phone', '')

    if request.method == 'POST':
        role = request.form['role']
        username = request.form['new_username']
        password = request.form['new_password']
        phone = request.form.get('new_phone', phone)
        full_name = request.form['new_full_name']
        upi_id = request.form.get('new_upi_id') if role == 'owner' else None
        whatsapp_enabled = 'whatsapp_enabled' in request.form

        existing_user = User.query.filter_by(phone=phone).first()
        if existing_user and existing_user.username.startswith('unregistered_'):
            existing_user.username = username
            existing_user.full_name = full_name
            existing_user.set_password(password)
            existing_user.upi_id = upi_id
            existing_user.whatsapp_enabled = whatsapp_enabled
            db.session.commit()
            flash("Registration complete! Your account is now active.", "success")
            return redirect(url_for('login'))
        else:
            if User.query.filter((User.username == username) | (User.phone == phone)).first():
                flash("Username or phone already exists", "danger")
                return redirect(url_for('register'))

            user = User(
                role=role,
                username=username,
                full_name=full_name,
                phone=phone,
                upi_id=upi_id,
                whatsapp_enabled=whatsapp_enabled
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            pending_tenancy = session.get('pending_tenancy')
            if pending_tenancy and pending_tenancy.get('phone') == phone:
                return redirect(url_for('complete_tenancy', phone=phone))

            flash("Registered successfully! Please login", "success")
            return redirect(url_for('login'))

    return render_template('register.html', phone=phone)


@app.route('/complete_tenancy/<phone>', methods=['GET', 'POST'])
@login_required
def complete_tenancy(phone):
    pending_tenancy = session.get('pending_tenancy')
    if not pending_tenancy or pending_tenancy.get('phone') != phone:
        flash("No pending tenancy found", "danger")
        return redirect(url_for('tenant_dashboard'))

    owner = User.query.get(pending_tenancy['owner_id'])
    if not owner:
        flash("Owner not found", "danger")
        return redirect(url_for('tenant_dashboard'))

    if request.method == 'POST':
        # Create property with address
        property = Property(
            name=pending_tenancy['property_name'],
            address=pending_tenancy.get('property_address', ''),  # Added address here
            owner_id=owner.id
        )
        db.session.add(property)
        db.session.flush()

        tenancy = Tenancy(
            owner_id=owner.id,
            tenant_id=current_user().id,
            property_id=property.id,
            rent_amount=pending_tenancy['rent_amount'],
            due_date=dt.datetime.strptime(pending_tenancy['due_date'], "%Y-%m-%d").date()
        )
        db.session.add(tenancy)
        session.pop('pending_tenancy', None)
        db.session.commit()

        content = f"Welcome to {property.name}! Your rent is ₹{tenancy.rent_amount} due on the {tenancy.due_date.day}th of each month."
        create_message(
            sender_id=owner.id,
            receiver_id=current_user().id,
            content=content,
            message_type='notification'
        )

        flash("Tenancy created successfully!", "success")
        return redirect(url_for('tenant_dashboard'))

    return render_template('complete_tenancy.html',
                           property_name=pending_tenancy['property_name'],
                           rent_amount=pending_tenancy['rent_amount'],
                           due_date=pending_tenancy['due_date'],
                           owner_name=owner.full_name)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", "success")
    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        user = current_user()

        # Admin can change password without current password
        is_admin = user.role == 'admin'

        if not is_admin and not user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('home'))

    return render_template('change_password.html')


# Messaging Routes
@app.route('/messages')
@login_required
def messages():
    user_id = current_user().id
    conversations = []

    contacts_query = db.session.query(
        Message.receiver_id.label('contact_id')
    ).filter(Message.sender_id == user_id
             ).union(
        db.session.query(
            Message.sender_id.label('contact_id')
        ).filter(Message.receiver_id == user_id)
    ).distinct().subquery()

    contacts = db.session.query(User).join(
        contacts_query, User.id == contacts_query.c.contact_id
    ).all()

    for contact in contacts:
        last_message = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == contact.id)) |
            ((Message.sender_id == contact.id) & (Message.receiver_id == user_id))
        ).order_by(Message.timestamp.desc()).first()

        unread_count = Message.query.filter_by(
            receiver_id=user_id,
            sender_id=contact.id,
            is_read=False
        ).count()

        conversations.append({
            'contact': contact,
            'last_message': last_message,
            'unread_count': unread_count
        })

    conversations.sort(key=lambda x: x['last_message'].timestamp, reverse=True)
    return render_template('messages.html', conversations=conversations)


@app.route('/messages/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def conversation(contact_id):
    contact = User.query.get_or_404(contact_id)
    user_id = current_user().id

    Message.query.filter_by(sender_id=contact_id, receiver_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()

    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == user_id))
    ).order_by(Message.timestamp.asc()).all()

    if request.method == 'POST':
        content = request.form['content']
        if content:
            create_message(
                sender_id=user_id,
                receiver_id=contact_id,
                content=content
            )
        return redirect(url_for('conversation', contact_id=contact_id))

    return render_template('conversation.html', contact=contact, messages=messages)


# Admin Routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    properties = Property.query.all()
    tenancies = Tenancy.query.all()
    payments = Payment.query.all()

    return render_template('admin/dashboard.html',
                           users=users,
                           properties=properties,
                           tenancies=tenancies,
                           payments=payments)


@app.route('/admin/users')
@admin_required
def view_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {user.username} has been {'activated' if user.is_active else 'deactivated'}", "success")
    return redirect(url_for('view_users'))


@app.route('/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig()
        db.session.add(config)
        db.session.commit()

    if request.method == 'POST':
        config.require_subscription = 'require_subscription' in request.form
        config.subscription_price = float(request.form.get('subscription_price', 500))
        config.subscription_duration = int(request.form.get('subscription_duration', 30))
        db.session.commit()
        flash("Configuration updated successfully!", "success")
        return redirect(url_for('admin_config'))

    return render_template('admin/config.html', config=config)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403, "Invalid CSRF token")

    user = User.query.get_or_404(user_id)

    if user.role == 'admin':
        flash("Cannot delete admin users", "danger")
        return redirect(url_for('view_users'))

    # Delete all associated data
    tenancies = Tenancy.query.filter(
        (Tenancy.owner_id == user_id) | (Tenancy.tenant_id == user_id)
    ).all()

    for tenancy in tenancies:
        Payment.query.filter_by(tenancy_id=tenancy.id).delete()
        db.session.delete(tenancy)

    Property.query.filter_by(owner_id=user_id).delete()

    Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).delete()

    db.session.delete(user)
    db.session.commit()

    flash(f"User {user.username} and all associated data deleted successfully", "success")
    return redirect(url_for('view_users'))


@app.route('/admin/grant_subscription/<int:user_id>')
@admin_required
def grant_subscription(user_id):
    user = User.query.get_or_404(user_id)
    duration = int(request.args.get('duration', 30))

    if user.subscription_end and user.subscription_end > dt.date.today():
        user.subscription_end += dt.timedelta(days=duration)
    else:
        user.subscription_end = dt.date.today() + dt.timedelta(days=duration)

    db.session.commit()
    flash(f"Subscription granted to {user.username} for {duration} days", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/change_password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_change_password(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()

            # Log this action
            create_message(
                sender_id=current_user().id,
                receiver_id=user.id,
                content=f"Your password was changed by admin {current_user().full_name}",
                message_type='notification'
            )

            flash(f"Password for {user.username} has been updated", "success")
            return redirect(url_for('view_users'))

    return render_template('admin/change_password.html', user=user)

# Subscription Routes
@app.route('/subscription')
@login_required
def subscription():
    config = SystemConfig.query.first()
    if not config or not config.require_subscription:
        flash("Subscription is not currently required", "info")
        return redirect(url_for('home'))

    return render_template('subscription.html')


@app.route('/pay_subscription', methods=['POST'])
@login_required
def pay_subscription():
    config = SystemConfig.query.first()
    if not config or not config.require_subscription:
        abort(400, "Subscription is not required")

    user = current_user()
    duration = config.subscription_duration

    if user.subscription_end and user.subscription_end > dt.date.today():
        user.subscription_end += dt.timedelta(days=duration)
    else:
        user.subscription_end = dt.date.today() + dt.timedelta(days=duration)

    db.session.commit()
    flash(f"Subscription payment successful! Your access is extended by {duration} days.", "success")

    if user.role == 'owner':
        return redirect(url_for('owner_dashboard'))
    elif user.role == 'tenant':
        return redirect(url_for('tenant_dashboard'))
    else:
        return redirect(url_for('home'))


# Owner Routes
@app.route('/owner/dashboard')
@owner_required
@subscription_required
def owner_dashboard():
    user = current_user()
    properties = Property.query.filter_by(owner_id=user.id).all()
    tenancies = Tenancy.query.filter_by(owner_id=user.id).all()

    pending_payments = []
    for tenancy in tenancies:
        payments = Payment.query.filter_by(tenancy_id=tenancy.id, status='pending').all()
        for payment in payments:
            pending_payments.append({
                'payment': payment,
                'tenant': tenancy.tenant,
                'property': tenancy.property
            })

    return render_template('owner/dashboard.html',
                           user=user,
                           properties=properties,
                           tenancies=tenancies,
                           pending_payments=pending_payments)


@app.route('/owner/tenants')
@owner_required
@subscription_required
def view_tenants():
    tenancies = Tenancy.query.filter_by(owner_id=current_user().id).all()

    registered_tenancies = []
    unregistered_tenancies = []

    for tenancy in tenancies:
        if tenancy.tenant.is_unregistered:
            unregistered_tenancies.append(tenancy)
        else:
            registered_tenancies.append(tenancy)

    return render_template('owner/tenants.html',
                           registered_tenancies=registered_tenancies,
                           unregistered_tenancies=unregistered_tenancies)


@app.route('/owner/send_invite/<int:tenant_id>')
@owner_required
@subscription_required
def send_invite(tenant_id):
    tenant = User.query.get_or_404(tenant_id)

    tenancies = Tenancy.query.filter_by(
        owner_id=current_user().id,
        tenant_id=tenant_id
    ).all()

    if not tenancies:
        abort(403, "This tenant doesn't belong to you")

    if not tenant.is_unregistered:
        flash("This tenant is already registered", "info")
        return redirect(url_for('view_tenants'))

    registration_link = url_for('register', phone=tenant.phone, _external=True)
    message = (
        f"📲 You've been invited by {current_user().full_name} to join RentTrack! "
        f"Please register to access your tenant account: {registration_link}"
    )

    if send_whatsapp_message(tenant.phone, message):
        flash("Invitation sent successfully!", "success")
    else:
        flash("Failed to send invitation", "warning")

    return redirect(url_for('view_tenants'))


@app.route('/owner/update_upi', methods=['POST'])
@owner_required
@subscription_required
def update_upi():
    new_upi = request.form['upi_id']
    if not new_upi:
        flash("UPI ID cannot be empty", "danger")
        return redirect(url_for('owner_dashboard'))

    user = current_user()
    user.upi_id = new_upi
    db.session.commit()
    flash("UPI ID updated successfully!", "success")
    return redirect(url_for('owner_dashboard'))


@app.route('/owner/add_tenant', methods=['GET', 'POST'])
@owner_required
@subscription_required
def add_tenant():
    if request.method == 'POST':
        tenant_phone = request.form['tenant_phone']
        property_name = request.form['property_name']
        property_address = request.form.get('property_address', '')  # Added address field
        rent_amount = float(request.form['rent_amount'])
        due_date = dt.datetime.strptime(request.form['due_date'], "%Y-%m-%d").date()

        if tenant_phone == current_user().phone:
            flash("You cannot add yourself as a tenant", "danger")
            return redirect(url_for('add_tenant'))

        tenant = User.query.filter_by(phone=tenant_phone).first()

        property = Property.query.filter_by(name=property_name, owner_id=current_user().id).first()
        if not property:
            property = Property(
                name=property_name,
                address=property_address,  # Added address here
                owner_id=current_user().id
            )
            db.session.add(property)
            db.session.flush()

        if not tenant:
            tenant = User(
                role='tenant',
                username=f"unregistered_{tenant_phone}",
                full_name=f"Unregistered ({tenant_phone})",
                phone=tenant_phone,
                is_active=True,
                whatsapp_enabled=True,
                password_hash=generate_password_hash(str(uuid.uuid4()))
            )
            db.session.add(tenant)
            db.session.flush()

            # Store pending tenancy with address in session
            session['pending_tenancy'] = {
                'phone': tenant_phone,
                'owner_id': current_user().id,
                'property_name': property_name,
                'property_address': property_address,  # Added address here
                'rent_amount': rent_amount,
                'due_date': due_date.strftime("%Y-%m-%d")
            }

        tenancy = Tenancy(
            owner_id=current_user().id,
            tenant_id=tenant.id,
            property_id=property.id,
            rent_amount=rent_amount,
            due_date=due_date
        )
        db.session.add(tenancy)
        db.session.commit()

        if tenant.is_unregistered:
            registration_link = url_for('register', phone=tenant_phone, _external=True)
            message = f"📲 You've been added as a tenant by {current_user().full_name}! Please register to access your account: {registration_link}"
            send_whatsapp_message(tenant_phone, message)
            flash("Tenant added successfully! Invitation sent via WhatsApp.", "success")
        else:
            content = f"You've been added as a tenant for {property.name}. Rent: ₹{rent_amount} due on {due_date.strftime('%d/%m')} each month."
            create_message(
                sender_id=current_user().id,
                receiver_id=tenant.id,
                content=content,
                message_type='notification'
            )
            flash(f"Tenant {tenant.full_name} added successfully!", "success")

        return redirect(url_for('view_tenants'))

    return render_template('owner/add_tenant.html')


@app.route('/owner/send_whatsapp/<int:tenant_id>', methods=['GET', 'POST'])
@owner_required
@subscription_required
def send_whatsapp(tenant_id):
    tenant = User.query.get_or_404(tenant_id)
    tenancies = Tenancy.query.filter_by(owner_id=current_user().id, tenant_id=tenant_id).all()

    if not tenancies:
        abort(403, "You don't have any tenancy with this tenant")

    if request.method == 'POST':
        message = request.form.get('message', '')

        if not message:
            flash("Message cannot be empty", "danger")
            return redirect(url_for('send_whatsapp', tenant_id=tenant_id))

        if send_whatsapp_message(tenant.phone, message):
            flash("WhatsApp message sent successfully!", "success")
        else:
            flash("Failed to send WhatsApp message", "warning")

        return redirect(url_for('owner_dashboard'))

    return render_template('owner/send_custom_message.html', tenant=tenant)


@app.route('/owner/confirm_payment/<int:payment_id>', methods=['GET', 'POST'])
@owner_required
@subscription_required
def owner_confirm_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    tenancy = payment.tenancy

    if tenancy.owner_id != current_user().id:
        abort(403)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'confirm':
            payment.status = 'paid'
            payment.receipt_generated = True
            db.session.commit()

            content = f"✅ Rent payment confirmed for {tenancy.property.name}. Amount: ₹{payment.amount}. Thank you!"
            create_message(
                sender_id=current_user().id,
                receiver_id=tenancy.tenant_id,
                content=content,
                message_type='payment'
            )

            flash("Payment confirmed! Receipt generated.", "success")
            return redirect(url_for('view_payments'))
        elif action == 'reject':
            reason = request.form.get('reason', 'No reason provided')
            payment.status = 'rejected'
            db.session.commit()

            content = f"❌ Rent payment rejected for {tenancy.property.name}. Reason: {reason}"
            create_message(
                sender_id=current_user().id,
                receiver_id=tenancy.tenant_id,
                content=content,
                message_type='payment'
            )
            flash("Payment rejected. Tenant has been notified.", "success")
            return redirect(url_for('view_payments'))

    return render_template('owner/confirm_payment_form.html',
                           payment=payment,
                           tenancy=tenancy)


@app.route('/download_receipt/<int:payment_id>')
@login_required
def download_receipt(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    tenancy = payment.tenancy

    if current_user().id not in [tenancy.owner_id, tenancy.tenant_id]:
        abort(403)

    html = render_template('receipt/receipt_content.html',
                           payment=payment,
                           tenancy=tenancy,
                           property=tenancy.property,
                           owner=tenancy.owner_user,
                           tenant=tenancy.tenant,
                           date=datetime.now())

    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=receipt_{payment.id}.pdf'

    return response


@app.route('/owner/edit_tenant/<int:tenancy_id>', methods=['GET', 'POST'])
@owner_required
@subscription_required
def edit_tenant(tenancy_id):
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.owner_id != current_user().id:
        abort(403)

    if request.method == 'POST':
        tenancy.rent_amount = float(request.form['rent_amount'])
        tenancy.due_date = dt.datetime.strptime(request.form['due_date'], "%Y-%m-%d").date()
        db.session.commit()
        flash("Tenancy updated successfully!", "success")
        return redirect(url_for('owner_dashboard'))

    return render_template('owner/edit_tenant.html', tenancy=tenancy)


@app.route('/owner/delete_tenant/<int:tenancy_id>', methods=['POST'])
@owner_required
@subscription_required
def delete_tenant(tenancy_id):
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.owner_id != current_user().id:
        abort(403)

    Payment.query.filter_by(tenancy_id=tenancy_id).delete()
    db.session.delete(tenancy)
    db.session.commit()

    flash("Tenant removed successfully!", "success")
    return redirect(url_for('owner_dashboard'))


@app.route('/owner/payments')
@owner_required
@subscription_required
def view_payments():
    owner_id = current_user().id
    payments = Payment.query.join(Tenancy).filter(
        Tenancy.owner_id == owner_id
    ).order_by(Payment.payment_date.desc()).all()

    return render_template('owner/payments.html', payments=payments)


# Tenant Routes
@app.route('/tenant/dashboard')
@tenant_required
@subscription_required
def tenant_dashboard():
    tenancies = Tenancy.query.filter_by(tenant_id=current_user().id).all()
    today = dt.date.today()

    for tenancy in tenancies:
        last_payment = Payment.query.filter_by(
            tenancy_id=tenancy.id,
            status='paid'
        ).order_by(Payment.payment_date.desc()).first()

        if last_payment:
            next_due_date = last_payment.payment_date + dt.timedelta(days=30)
        else:
            next_due_date = tenancy.due_date

        if next_due_date < today:
            content = f"⚠️ Rent Overdue! {tenancy.property.name} rent was due on {next_due_date.strftime('%Y-%m-%d')}"
            create_message(
                sender_id=tenancy.owner_id,
                receiver_id=current_user().id,
                content=content,
                message_type='warning'
            )

    return render_template('tenant/dashboard.html', tenancies=tenancies)


@app.route('/tenant/payment_history/<int:tenancy_id>')
@tenant_required
@subscription_required
def tenant_payment_history(tenancy_id):
    tenancy_obj = Tenancy.query.get_or_404(tenancy_id)
    if tenancy_obj.tenant_id != current_user().id:
        abort(403)

    payments_list = Payment.query.filter_by(tenancy_id=tenancy_id).order_by(Payment.payment_date.desc()).all()
    owner_obj = User.query.get(tenancy_obj.owner_id)
    tenant_obj = User.query.get(tenancy_obj.tenant_id)
    property_obj = Property.query.get(tenancy_obj.property_id)

    # Serialize objects
    serialized_tenancy = serialize_sqla_obj(tenancy_obj)
    serialized_payments = [serialize_sqla_obj(p) for p in payments_list]
    serialized_owner = serialize_sqla_obj(owner_obj)
    serialized_tenant = serialize_sqla_obj(tenant_obj)
    serialized_property = serialize_sqla_obj(property_obj)

    return render_template('tenant/payment_history.html',
                           tenancy=serialized_tenancy,
                           payments=serialized_payments,
                           owner=serialized_owner,
                           tenant=serialized_tenant,
                           property=serialized_property)


@app.route('/tenant/pay_rent/<int:tenancy_id>', methods=['GET', 'POST'])
@tenant_required
@subscription_required
def pay_rent(tenancy_id):
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.tenant_id != current_user().id:
        abort(403)

    owner = User.query.get(tenancy.owner_id)

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            abort(400, 'Invalid CSRF token')

        upi_txn_id = request.form.get('upi_txn_id')
        notes = request.form.get('notes', '')

        payment = Payment(
            tenancy_id=tenancy.id,
            amount=tenancy.rent_amount,
            status='pending',
            upi_txn_id=upi_txn_id,
            notes=notes or f"Payment for {tenancy.property.name}"
        )
        db.session.add(payment)
        db.session.commit()

        content = f"💳 Payment initiated by {current_user().full_name} for {tenancy.property.name}. Amount: ₹{tenancy.rent_amount}. UPI TXN ID: {upi_txn_id}. Notes: {notes}"
        create_message(
            sender_id=current_user().id,
            receiver_id=tenancy.owner_id,
            content=content,
            message_type='payment'
        )

        flash("Payment recorded! Owner has been notified to verify.", "success")
        return redirect(url_for('tenant_dashboard'))

    upi_link = None
    if owner.upi_id:
        upi_link = (
            f"upi://pay?pa={owner.upi_id}"
            f"&pn={owner.full_name}"
            f"&am={float(tenancy.rent_amount)}"
            f"&tn=Rent for {tenancy.property.name}"
            f"&cu=INR"
        )

    return render_template('tenant/pay_rent.html',
                           tenancy=tenancy,
                           owner=owner,
                           upi_link=upi_link)


# Initialize Database
if __name__ == '__main__':
    init_db()
    app.run(debug=True)