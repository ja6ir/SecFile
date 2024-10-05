from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, after_this_request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User, File, Backup, FileAccess, RecoveryRequest
from .utils.encryption import encrypt_file, decrypt_file
from .utils.backup import create_backup, recover_backup
from app import login_manager
import os
import time

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Routes for authentication
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('main.register'))
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'), role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('main.login'))
        login_user(user)
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.login'))

# Routes for user
@main.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('main.admin_dashboard'))
    user_files = File.query.filter_by(owner_id=current_user.id).all()
    backups = Backup.query.filter_by(owner_id=current_user.id).all()

    shared_file_ids = [access.file_id for access in FileAccess.query.filter_by(user_id=current_user.id).all()]
    shared_files = File.query.filter(File.id.in_(shared_file_ids)).all()

    backup_file_ids = [backup.file_id for backup in backups]
    files_in_backups = File.query.filter(File.id.in_(backup_file_ids)).all()

    # Create a dictionary to map file_id to (filename, uploaded_at)
    file_info = {file.id: (file.filename, file.uploaded_at) for file in files_in_backups}

    # Add filename and uploaded_at to each backup
    for backup in backups:
        if backup.file_id in file_info:
            backup.filename, backup.uploaded_at = file_info[backup.file_id]
        else:
            backup.filename, backup.uploaded_at = None, None  # Handle cases where no file is found
    return render_template('user_dashboard.html', files=user_files, shared_files=shared_files, backups = backups)

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('No file selected.', 'warning')
            return redirect(request.url)
        encrypted_file_path, encryption_key, checksum = encrypt_file(file)
        new_file = File(filename=file.filename, encrypted_path=encrypted_file_path, encryption_key=encryption_key, checksum=checksum, owner_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('user_dashboard.html')

@main.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        access = FileAccess.query.filter_by(file_id=file_id, user_id=current_user.id).first()
        if not access or access.permission not in ['read', 'write']:
            flash('Access denied.', 'danger')
            return redirect(url_for('main.dashboard'))
    decrypted_file_path = decrypt_file(file.encrypted_path, file.encryption_key, file.filename)
    @after_this_request
    def delete_file(response):
        try:
            time.sleep(3)
            os.remove(decrypted_file_path)
        except Exception as e:
            # You can log the error here if necessary
            print(f"Error deleting file: {e}")
        return response
    return send_file(decrypted_file_path, as_attachment=True, download_name=file.filename)

@main.route('/delete/<int:file_id>', methods=['GET'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('main.dashboard'))
    if os.path.exists(file.encrypted_path):
        os.remove(file.encrypted_path)
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully.', 'success')
    return redirect(url_for('main.dashboard'))

# Backup and recovery routes
@main.route('/backup/<int:file_id>', methods=['POST'])
@login_required
def backup_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('main.dashboard'))
    backup_path = create_backup(file.encrypted_path)
    new_backup = Backup(file_id=file.id, backup_path=backup_path, owner_id =current_user.id)
    db.session.add(new_backup)
    db.session.commit()
    flash('Backup created successfully.', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/request_recovery/<int:file_id>', methods=['POST'])
@login_required
def request_recovery(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('main.dashboard'))
    new_request = RecoveryRequest(user_id=current_user.id, file_id=file.id, status='Pending')
    db.session.add(new_request)
    db.session.commit()
    flash('Recovery request submitted.', 'info')
    return redirect(url_for('main.dashboard'))

@main.route('/shared', methods=['POST'])
@login_required
def share_file():
    
    if request.method == 'POST':
        file_id = request.form.get('username')
        username = request.form.get('username')
        permission = request.form.get('permission')
        file = File.query.get_or_404(file_id)
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('main.dashboard'))
        if FileAccess.query.filter_by(file_id=file_id, user_id=user.id).first():
            flash('File already shared with this user.', 'warning')
            return redirect(url_for('main.dashboard'))
        new_access = FileAccess(file_id=file_id, user_id=user.id, permission=permission)
        db.session.add(new_access)
        db.session.commit()
        flash('File shared successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.dashboard'))

# Admin Routes
@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    users = User.query.all()
    files = File.query.all()
    recovery_requests = RecoveryRequest.query.all()
    return render_template('admin_dashboard.html', users=users, files=files, recovery_requests=recovery_requests)

@main.route('/admin/recovery_approval/<int:request_id>', methods=['POST'])
@login_required
def approve_recovery(request_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    recovery_request = RecoveryRequest.query.get_or_404(request_id)
    file = File.query.get_or_404(recovery_request.file_id)
    backup = Backup.query.filter_by(file_id=file.id).first()
    if not backup:
        flash('No backup available.', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    recover_backup(backup.backup_path, file.encrypted_path)
    recovery_request.status = 'Approved'
    db.session.commit()
    flash('Recovery approved and completed.', 'success')
    return redirect(url_for('main.admin_dashboard'))
