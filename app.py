from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'technovalley-secret-key-change-in-prod'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mail.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

MAIL_DOMAIN = "hacker.email"


# ==================== MODELS ====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def email(self):
        return f"{self.username}@{MAIL_DOMAIN}"

    def set_password(self, p):
        self.password_hash = generate_password_hash(p)

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)


class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(500), default='(no subject)')
    body = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    thread_id = db.Column(db.Integer, nullable=True)
    in_reply_to = db.Column(db.Integer, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipients = db.relationship('Recipient', backref='email',
                                 cascade='all, delete-orphan')


class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kind = db.Column(db.String(6), default='to')   # to / cc / bcc / sent
    is_read = db.Column(db.Boolean, default=False)
    is_starred = db.Column(db.Boolean, default=False)
    is_trash = db.Column(db.Boolean, default=False)
    is_important = db.Column(db.Boolean, default=False)

    user = db.relationship('User')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==================== HELPERS ====================
def deliver_email(sender, to_str, cc_str, bcc_str, subject, body,
                  in_reply_to=None, thread_id=None):
    email = Email(
        sender_id=sender.id,
        subject=subject or '(no subject)',
        body=body or '',
        in_reply_to=in_reply_to,
        thread_id=thread_id or in_reply_to,
    )
    db.session.add(email)
    db.session.flush()

    delivered = set()

    def add(field, kind):
        if not field:
            return
        for raw in field.replace(';', ',').split(','):
            addr = raw.strip().lower()
            if not addr:
                continue
            if '@' not in addr:
                addr = f"{addr}@{MAIL_DOMAIN}"
            if not addr.endswith(f"@{MAIL_DOMAIN}"):
                continue
            username = addr.split('@')[0]
            user = User.query.filter_by(username=username).first()
            if user and user.id not in delivered:
                delivered.add(user.id)
                db.session.add(Recipient(
                    email_id=email.id, user_id=user.id, kind=kind
                ))

    add(to_str, 'to')
    add(cc_str, 'cc')
    add(bcc_str, 'bcc')

    db.session.add(Recipient(
        email_id=email.id, user_id=sender.id, kind='sent', is_read=True
    ))

    db.session.commit()
    return email


def unread_count_for(user):
    """Count of unread inbox mails (to/cc/bcc, not trashed)."""
    return (Recipient.query
            .filter_by(user_id=user.id, is_trash=False, is_read=False)
            .filter(Recipient.kind.in_(['to', 'cc', 'bcc']))
            .count())


def sent_count_for(user):
    return Recipient.query.filter_by(user_id=user.id, kind='sent').count()


def starred_count_for(user):
    return Recipient.query.filter_by(
        user_id=user.id, is_starred=True, is_trash=False).count()


@app.context_processor
def inject_counts():
    if current_user.is_authenticated:
        return {
            'inbox_unread': unread_count_for(current_user),
            'sent_count_badge': sent_count_for(current_user),
            'starred_count_badge': starred_count_for(current_user),
            'current_year': datetime.utcnow().year,
        }
    return {'current_year': datetime.utcnow().year}


# ==================== ROUTES ====================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('inbox'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email_input = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if '@' in email_input:
            parts = email_input.split('@')
            username = parts[0]
            if parts[1] != MAIL_DOMAIN:
                flash(f'Email must end with @{MAIL_DOMAIN}', 'error')
                return redirect(url_for('register'))
        else:
            username = email_input

        if not username or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if not username.replace('.', '').replace('_', '').isalnum():
            flash('Username can only contain letters, numbers, dots and underscores.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('That email ID is already taken.', 'error')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash(f'Account created! Your email is {user.email}', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', domain=MAIL_DOMAIN)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_input = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        username = email_input.split('@')[0] if '@' in email_input else email_input

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('inbox'))

        flash('Invalid email or password.', 'error')

    return render_template('login.html', domain=MAIL_DOMAIN)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/inbox')
@login_required
def inbox():
    recips = (Recipient.query
              .filter_by(user_id=current_user.id, is_trash=False)
              .filter(Recipient.kind.in_(['to', 'cc', 'bcc']))
              .join(Email)
              .order_by(Email.created_at.desc())
              .all())
    emails = [r.email for r in recips]
    return render_template('inbox.html', emails=emails, recips=recips,
                           folder='Inbox', active='inbox')


@app.route('/sent')
@login_required
def sent():
    recips = (Recipient.query
              .filter_by(user_id=current_user.id, kind='sent')
              .join(Email)
              .order_by(Email.created_at.desc())
              .all())
    emails = [r.email for r in recips]
    return render_template('inbox.html', emails=emails, recips=recips,
                           folder='Sent', active='sent')


@app.route('/starred')
@login_required
def starred():
    recips = (Recipient.query
              .filter_by(user_id=current_user.id, is_starred=True, is_trash=False)
              .join(Email)
              .order_by(Email.created_at.desc())
              .all())
    emails = [r.email for r in recips]
    return render_template('inbox.html', emails=emails, recips=recips,
                           folder='Starred', active='starred')


@app.route('/trash')
@login_required
def trash():
    recips = (Recipient.query
              .filter_by(user_id=current_user.id, is_trash=True)
              .join(Email)
              .order_by(Email.created_at.desc())
              .all())
    emails = [r.email for r in recips]
    return render_template('inbox.html', emails=emails, recips=recips,
                           folder='Trash', active='trash')


@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    if request.method == 'POST':
        to = request.form.get('to', '').strip()
        cc = request.form.get('cc', '').strip()
        bcc = request.form.get('bcc', '').strip()
        subject = request.form.get('subject', '').strip() or '(no subject)'
        body = request.form.get('body', '').strip()
        in_reply_to = request.form.get('in_reply_to', type=int)
        thread_id = request.form.get('thread_id', type=int)

        if not to:
            flash('Please specify at least one recipient.', 'error')
            return redirect(url_for('compose'))

        email = deliver_email(current_user, to, cc, bcc, subject, body,
                              in_reply_to=in_reply_to, thread_id=thread_id)
        if not email:
            flash('No valid  recipients found.', 'error')
            return redirect(url_for('compose'))

        flash('Message sent.', 'success')
        return redirect(url_for('sent'))

    reply_to = request.args.get('reply_to', type=int)
    reply_all = request.args.get('reply_all', type=int)
    forward = request.args.get('forward', type=int)

    prefill = {}
    if reply_to or reply_all or forward:
        eid = reply_to or reply_all or forward
        orig = Email.query.get(eid)
        if orig:
            if forward:
                prefill = {
                    'subject': f"Fwd: {orig.subject}" if not orig.subject.lower().startswith('fwd:') else orig.subject,
                    'body': (f"\n\n\n---------- Forwarded message ----------\n"
                             f"From: {orig.sender.email}\n"
                             f"Date: {orig.created_at.strftime('%b %d, %Y %I:%M %p')}\n"
                             f"Subject: {orig.subject}\n"
                             f"To: {', '.join(r.user.email for r in orig.recipients if r.kind in ('to','cc','bcc'))}\n\n"
                             f"{orig.body}"),
                }
            else:
                if reply_all:
                    others = [r.user.email for r in orig.recipients
                              if r.kind in ('to', 'cc')
                              and r.user_id != current_user.id]
                    prefill['to'] = orig.sender.email
                    prefill['cc'] = ', '.join(o for o in others if o != orig.sender.email)
                else:
                    prefill['to'] = orig.sender.email

                prefill['subject'] = (orig.subject if orig.subject.lower().startswith('re:')
                                      else f"Re: {orig.subject}")
                prefill['body'] = (f"\n\n\nOn {orig.created_at.strftime('%b %d, %Y at %I:%M %p')}, "
                                   f"{orig.sender.email} wrote:\n> "
                                   + orig.body.replace('\n', '\n> '))
                prefill['in_reply_to'] = orig.id
                prefill['thread_id'] = orig.thread_id or orig.id

    return render_template('compose.html', domain=MAIL_DOMAIN, prefill=prefill)


@app.route('/email/<int:email_id>')
@login_required
def view_email(email_id):
    email = Email.query.get_or_404(email_id)

    recip = Recipient.query.filter_by(
        email_id=email.id, user_id=current_user.id).first()
    if recip and not recip.is_read:
        recip.is_read = True
        db.session.commit()

    tid = email.thread_id or email.id
    thread = (Email.query
              .filter((Email.id == tid) | (Email.thread_id == tid))
              .order_by(Email.created_at.asc())
              .all())

    return render_template('view_email.html', email=email,
                           thread=thread, recip=recip)


@app.route('/email/<int:email_id>/star', methods=['POST'])
@login_required
def toggle_star(email_id):
    r = Recipient.query.filter_by(
        email_id=email_id, user_id=current_user.id).first_or_404()
    r.is_starred = not r.is_starred
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'starred': r.is_starred})
    return redirect(request.referrer or url_for('inbox'))


@app.route('/email/<int:email_id>/important', methods=['POST'])
@login_required
def toggle_important(email_id):
    r = Recipient.query.filter_by(
        email_id=email_id, user_id=current_user.id).first_or_404()
    r.is_important = not r.is_important
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'important': r.is_important})
    return redirect(request.referrer or url_for('inbox'))


@app.route('/email/<int:email_id>/trash', methods=['POST'])
@login_required
def move_to_trash(email_id):
    r = Recipient.query.filter_by(
        email_id=email_id, user_id=current_user.id).first_or_404()
    r.is_trash = True
    db.session.commit()
    flash('Conversation moved to Trash.', 'success')
    return redirect(url_for('inbox'))


@app.route('/email/<int:email_id>/delete', methods=['POST'])
@login_required
def delete_email(email_id):
    r = Recipient.query.filter_by(
        email_id=email_id, user_id=current_user.id).first_or_404()
    db.session.delete(r)
    db.session.flush()
    if Recipient.query.filter_by(email_id=email_id).count() == 0:
        e = Email.query.get(email_id)
        if e:
            db.session.delete(e)
    db.session.commit()
    flash('Message deleted forever.', 'success')
    return redirect(url_for('trash'))


# API for live badge polling
@app.route('/api/unread-count')
@login_required
def api_unread_count():
    return jsonify({
        'inbox': unread_count_for(current_user),
        'starred': starred_count_for(current_user),
        'sent': sent_count_for(current_user),
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
