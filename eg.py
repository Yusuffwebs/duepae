from datetime import datetime
import datetime as dt
import pdfkit
import os
from xhtml2pdf import pisa
from io import BytesIO





from flask import make_response
import tempfile
import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, g, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rent.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Admin configuration
ADMIN_USERNAME = "yusuffAseher"
ADMIN_PASSWORD = "Asher24yusa"


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'owner', 'tenant'
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    upi_id = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    subscription_end = db.Column(db.Date, nullable=True)
    whatsapp_enabled = db.Column(db.Boolean, default=True)

    # Fixed relationships
    owned_properties = relationship("Property", back_populates="owner", lazy=True)
    tenancies_as_tenant = relationship("Tenancy", foreign_keys="Tenancy.tenant_id", back_populates="tenant", lazy=True)
    tenancies_as_owner = relationship("Tenancy", foreign_keys="Tenancy.owner_id", back_populates="owner_user",
                                      lazy=True)
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender", lazy=True)
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver",
                                     lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def has_active_subscription(self):
        if self.role == 'admin':
            return True
        return self.subscription_end and self.subscription_end >= dt.date.today()


class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = relationship("User", back_populates="owned_properties")
    tenancies = relationship("Tenancy", back_populates="property", lazy=True)


class Tenancy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    rent_amount = db.Column(db.Numeric(10, 2), nullable=False)
    due_date = db.Column(db.Date, nullable=False)

    # Fixed relationships
    owner_user = relationship("User", foreign_keys=[owner_id], back_populates="tenancies_as_owner")
    tenant = relationship("User", foreign_keys=[tenant_id], back_populates="tenancies_as_tenant")
    property = relationship("Property", back_populates="tenancies")
    payments = relationship("Payment", back_populates="tenancy", lazy=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenancy_id = db.Column(db.Integer, db.ForeignKey('tenancy.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    payment_date = db.Column(db.Date, default=dt.date.today)
    status = db.Column(db.String(20), default='pending')  # pending, paid, confirmed
    upi_txn_id = db.Column(db.String(120))
    notes = db.Column(db.String(255))
    receipt_generated = db.Column(db.Boolean, default=False)

    tenancy = relationship("Tenancy", back_populates="payments")


class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    require_subscription = db.Column(db.Boolean, default=False)
    subscription_price = db.Column(db.Numeric(10, 2), default=500.00)
    subscription_duration = db.Column(db.Integer, default=30)  # in days


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    message_type = db.Column(db.String(20), default='notification')  # notification, payment, warning

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")


# Helper Functions
def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def send_whatsapp_message(phone, message):
    """Simulate sending WhatsApp message"""
    print(f"Sending WhatsApp to {phone}: {message}")
    return True


def create_message(sender_id, receiver_id, content, message_type='notification'):
    """Create and send a message"""
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
    if current_user():
        unread_count = db.session.query(Message).filter_by(
            receiver_id=current_user().id,
            is_read=False
        ).count()
    return dict(user=g.user, datetime=dt.datetime, config=config, unread_count=unread_count)


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
        if not current_user() or current_user().role != 'owner':
            abort(403)
        return f(*args, **kwargs)

    return decorated


def tenant_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user() or current_user().role != 'tenant':
            abort(403)
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user() or current_user().role != 'admin':
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
        db.create_all()

        # Create system config if not exists
        if not SystemConfig.query.first():
            db.session.add(SystemConfig())
            db.session.commit()

        # Create admin user if not exists
        admin = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                role='admin',
                username=ADMIN_USERNAME,
                full_name="Admin User",
                phone="0000000000",
                is_active=True
            )
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
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
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            session['user_id'] = user.id
            flash("Login successful!", "success")

            if user.role == 'tenant':
                tenancies = Tenancy.query.filter_by(tenant_id=user.id).all()
                today = dt.date.today()
                for tenancy in tenancies:
                    # Fixed overdue check
                    last_payment = Payment.query.filter_by(
                        tenancy_id=tenancy.id
                    ).order_by(Payment.payment_date.desc()).first()

                    # Check if last payment covers current due date
                    if not last_payment or last_payment.payment_date < tenancy.due_date:
                        # Check if due date has passed
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

        flash("Invalid credentials or account disabled", "danger")

    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form['role']
        username = request.form['new_username']
        password = request.form['new_password']
        phone = request.form['new_phone']
        full_name = request.form['new_full_name']
        upi_id = request.form.get('new_upi_id') if role == 'owner' else None
        whatsapp_enabled = 'whatsapp_enabled' in request.form

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

    return render_template('auth/register.html')


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
        property = Property.query.filter_by(name=pending_tenancy['property_name'], owner_id=owner.id).first()
        if not property:
            property = Property(name=pending_tenancy['property_name'], owner_id=owner.id)
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
        # Clear session after completing tenancy
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

    return render_template('auth/complete_tenancy.html',
                           property_name=pending_tenancy['property_name'],
                           rent_amount=pending_tenancy['rent_amount'],
                           due_date=pending_tenancy['due_date'],
                           owner_name=owner.full_name)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", "success")
    return redirect(url_for('login'))


# Messaging Routes
@app.route('/messages')
@login_required
def messages():
    user_id = current_user().id
    sent_messages = Message.query.filter_by(sender_id=user_id).all()
    received_messages = Message.query.filter_by(receiver_id=user_id).all()

    contacts = set()
    for msg in sent_messages:
        contacts.add(msg.receiver_id)
    for msg in received_messages:
        contacts.add(msg.sender_id)

    conversations = []
    for contact_id in contacts:
        contact = User.query.get(contact_id)
        last_message = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == contact_id)) |
            ((Message.sender_id == contact_id) & (Message.receiver_id == user_id))
        ).order_by(Message.timestamp.desc()).first()

        unread_count = Message.query.filter_by(
            receiver_id=user_id,
            sender_id=contact_id,
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


@app.route('/admin/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {user.username} has been {'activated' if user.is_active else 'deactivated'}", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    config = SystemConfig.query.first() or SystemConfig()

    if request.method == 'POST':
        config.require_subscription = 'require_subscription' in request.form
        config.subscription_price = float(request.form.get('subscription_price', 500))
        config.subscription_duration = int(request.form.get('subscription_duration', 30))
        db.session.add(config)
        db.session.commit()
        flash("Configuration updated successfully!", "success")
        return redirect(url_for('admin_config'))

    return render_template('admin/config.html', config=config)


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
        rent_amount = request.form['rent_amount']
        due_date = dt.datetime.strptime(request.form['due_date'], "%Y-%m-%d").date()

        if tenant_phone == current_user().phone:
            flash("You cannot add yourself as a tenant", "danger")
            return redirect(url_for('add_tenant'))

        tenant = User.query.filter_by(phone=tenant_phone).first()

        if not tenant:
            tenant = User(
                role='tenant',
                username=f"unregistered_{tenant_phone}",
                full_name=f"Unregistered Tenant ({tenant_phone})",
                phone=tenant_phone,
                is_active=True
            )
            db.session.add(tenant)
            db.session.flush()
            flash("Tenant not registered. Created placeholder account.", "warning")

        property = Property.query.filter_by(name=property_name, owner_id=current_user().id).first()
        if not property:
            property = Property(name=property_name, owner_id=current_user().id)
            db.session.add(property)
            db.session.flush()

        existing_tenancy = Tenancy.query.filter_by(
            owner_id=current_user().id,
            tenant_id=tenant.id,
            property_id=property.id
        ).first()

        if existing_tenancy:
            flash("This tenant is already linked to this property", "warning")
            return redirect(url_for('owner_dashboard'))

        tenancy = Tenancy(
            owner_id=current_user().id,
            tenant_id=tenant.id,
            property_id=property.id,
            rent_amount=rent_amount,
            due_date=due_date
        )
        db.session.add(tenancy)
        db.session.commit()

        content = f"You've been added as a tenant for {property.name}. Rent: ₹{rent_amount} due on {due_date.strftime('%d/%m')} each month."
        create_message(
            sender_id=current_user().id,
            receiver_id=tenant.id,
            content=content,
            message_type='notification'
        )

        flash(f"Tenant {tenant.full_name} added successfully!", "success")
        return redirect(url_for('owner_dashboard'))

    return render_template('owner/add_tenant.html')


# Update the confirm_payment route
@app.route('/owner/confirm_payment/<int:payment_id>', methods=['GET', 'POST'])
@owner_required
@subscription_required
def confirm_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    tenancy = payment.tenancy

    if tenancy.owner_id != current_user().id:
        abort(403)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'confirm':
            payment.status = 'paid'
            db.session.commit()

            # Notify tenant BEFORE generating PDF
            content = f"✅ Rent payment confirmed for {tenancy.property.name}! Receipt generated."
            create_message(
                sender_id=current_user().id,
                receiver_id=tenancy.tenant_id,
                content=content,
                message_type='payment'
            )

            flash("Payment confirmed! Downloading receipt...", "success")
            return redirect(url_for('download_receipt', payment_id=payment.id))

        elif action == 'reject':
            payment.status = 'rejected'
            reason = request.form.get('reason', 'No reason provided')

            content = f"❌ Rent payment rejected for {tenancy.property.name}. Reason: {reason}"
            create_message(
                sender_id=current_user().id,
                receiver_id=tenancy.tenant_id,
                content=content,
                message_type='payment'
            )

            db.session.commit()
            flash("Payment rejected. Tenant has been notified.", "success")
            return redirect(url_for('owner_dashboard'))

    return render_template('owner/verify_rent_payment.html', payment=payment, tenancy=tenancy)




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

    # Create PDF
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)

    # Create response
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
        tenancy.rent_amount = request.form['rent_amount']
        tenancy.due_date = dt.datetime.strptime(request.form['due_date'], "%Y-%m-%d").date()
        db.session.commit()
        flash("Tenancy updated successfully!", "success")
        return redirect(url_for('owner_dashboard'))

    return render_template('owner/edit_tenant.html', tenancy=tenancy)


# Add this after the edit_tenant route
@app.route('/owner/delete_tenant/<int:tenancy_id>', methods=['POST'])
@owner_required
@subscription_required
def delete_tenant(tenancy_id):
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.owner_id != current_user().id:
        abort(403)

    # Delete all payments associated with this tenancy
    Payment.query.filter_by(tenancy_id=tenancy_id).delete()

    # Delete the tenancy
    db.session.delete(tenancy)
    db.session.commit()

    flash("Tenant removed successfully!", "success")
    return redirect(url_for('owner_dashboard'))


# ... (previous imports and setup)

@app.context_processor
def inject_user():
    config = SystemConfig.query.first() or SystemConfig()
    unread_count = 0
    user = g.user  # This is equivalent to current_user()

    if user:
        unread_count = Message.query.filter_by(
            receiver_id=user.id,
            is_read=False
        ).count()

    return dict(
        user=user,
        current_user=user,  # Alias for template compatibility
        datetime=dt.datetime,
        config=config,
        unread_count=unread_count
    )


# ... (other routes and functions)

@app.route('/owner/payments')
@owner_required
@subscription_required
def view_payments():
    owner_id = current_user().id
    tenancies = Tenancy.query.filter_by(owner_id=owner_id).all()
    tenancy_ids = [t.id for t in tenancies]
    payments = Payment.query.filter(
        Payment.tenancy_id.in_(tenancy_ids)
    ).order_by(Payment.payment_date.desc()).all()

    return render_template('owner/payments.html', payments=payments)


# ... (rest of the code)
# Tenant Routes
@app.route('/tenant/dashboard')
@tenant_required
@subscription_required
def tenant_dashboard():
    tenancies = Tenancy.query.filter_by(tenant_id=current_user().id).all()
    today = dt.date.today()

    for tenancy in tenancies:
        # Check if rent is overdue
        last_payment = Payment.query.filter_by(
            tenancy_id=tenancy.id,
            status='paid'
        ).order_by(Payment.payment_date.desc()).first()

        # Calculate next due date
        if last_payment:
            next_due_date = last_payment.payment_date + dt.timedelta(days=30)
        else:
            next_due_date = tenancy.due_date

        # Check if payment is overdue
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
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.tenant_id != current_user().id:
        abort(403)

    payments = Payment.query.filter_by(tenancy_id=tenancy_id).order_by(Payment.payment_date.desc()).all()
    return render_template('tenant/payment_history.html', tenancy=tenancy, payments=payments)


@app.route('/tenant/pay_rent/<int:tenancy_id>', methods=['GET', 'POST'])
@tenant_required
@subscription_required
def pay_rent(tenancy_id):
    tenancy = Tenancy.query.get_or_404(tenancy_id)
    if tenancy.tenant_id != current_user().id:
        abort(403)

    owner = User.query.get(tenancy.owner_id)

    if request.method == 'POST':
        payment_method = request.form.get('payment_method')

        if payment_method == 'manual':
            upi_txn_id = request.form.get('upi_txn_id', '')
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

            content = f"🔄 Rent payment marked as paid by {current_user().full_name} for {tenancy.property.name}. Please confirm."
            create_message(
                sender_id=current_user().id,
                receiver_id=tenancy.owner_id,
                content=content,
                message_type='payment'
            )

            flash("Payment recorded! Waiting for owner confirmation.", "success")
            return redirect(url_for('tenant_dashboard'))
        else:
            flash("Invalid payment method selected", "error")
            return redirect(url_for('pay_rent', tenancy_id=tenancy.id))

    # Generate UPI deep link (for GET request)
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