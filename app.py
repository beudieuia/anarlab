import io
import math
import json
import pyodbc
import pandas as pd
import pdfkit
import traceback
import os
from datetime import datetime, timedelta
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from waitress import serve
from sqlalchemy import create_engine, text, bindparam
import urllib.parse
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
import urllib.parse
from sqlalchemy import create_engine
from weasyprint import HTML

connection_string = "Server=tcp:anarpam-lims.database.windows.net,1433;Initial Catalog=MineralLabDB;Persist Security Info=False;User ID=anarpamlabo;Password=Anarpam_123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

# --- App Configuration & DB Connection ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'
DB_SERVER = 'AHMED\\SQLEXPRESS'
DB_NAME = 'MineralLabDB'
DB_USERNAME = ""
DB_PASSWORD = ""
if DB_USERNAME and DB_PASSWORD:
    connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_NAME};UID={DB_USERNAME};PWD={DB_PASSWORD}'
else:
    connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_NAME};Trusted_Connection=yes;'

# --- NOUVELLE MÉTHODE DE CONNEXION POUR AZURE ---
# Récupère la chaîne de connexion depuis les paramètres de l'application Azure
connection_string = os.environ.get('AZURE_SQL_CONNECTIONSTRING')

engine = None
if connection_string:
    try:
        # On doit spécifier le driver ODBC pour Azure App Service
        quoted_conn_str = urllib.parse.quote_plus(connection_string)
        
        engine = create_engine(
            f'mssql+pyodbc:///?odbc_connect={quoted_conn_str}&driver=ODBC+Driver+17+for+SQL+Server',
            pool_size=10, max_overflow=5, pool_timeout=30, pool_recycle=1800
        )
        print("Successfully created SQLAlchemy engine for Azure SQL from environment variable.")
    except Exception as e:
        print(f"Failed to create SQLAlchemy engine from environment variable: {e}")
        engine = None
else:
    print("DATABASE_CONNECTION_STRING environment variable not found.")

# --- UPDATED: ENGINE WITH CONNECTION POOLING ---
try:
    quoted_conn_str = urllib.parse.quote_plus(connection_string).replace('+', '%2B')
    engine = create_engine(
        f'mssql+pyodbc:///?odbc_connect={quoted_conn_str}&driver=ODBC+Driver+17+for+SQL+Server',
        pool_size=10, max_overflow=5, pool_timeout=30, pool_recycle=1800
    )
    print("Successfully created SQLAlchemy engine for Azure SQL.")
except Exception as e:
    print(f"Failed to create SQLAlchemy engine: {e}")
    engine = None


# --- UPDATED: GET CONNECTION FROM POOL ---
def get_db_connection():
    if not engine:
        print("Database engine is not initialized.")
        return None
    try:
        conn = engine.connect()
        return conn
    except Exception as e:
        print(f"Database Connection Pool Error: {e}")
        traceback.print_exc()
        return None

# --- Reusable Functions & Classes ---
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal): return float(obj)
        if isinstance(obj, datetime): return obj.isoformat()
        return super(CustomJSONEncoder, self).default(obj)


def log_action(conn, batch_id, action_description):
    """
    Enregistre une action dans AuditLog en utilisant une connexion BDD existante.
    NOTE : Cette fonction doit être appelée à l'intérieur d'une transaction existante.
    """
    if not current_user.is_authenticated: return
    log_user_id = current_user.id
    
    # N'ouvre plus sa propre connexion, mais utilise celle fournie
    try:
        conn.execute(
            text("INSERT INTO AuditLog (BatchID, UserID, Action) VALUES (:batch_id, :user_id, :action)"), 
            {'batch_id': batch_id, 'user_id': log_user_id, 'action': action_description}
        )
    except Exception as e:
        # Ne pas masquer l'erreur, la laisser remonter pour que la transaction principale soit annulée
        print(f"ÉCHEC CRITIQUE DU JOURNAL D'AUDIT : {e}")
        raise

def generate_pdf_response(html_string, filename_prefix):
    try:
        pdf_bytes = HTML(string=html_string).write_pdf()
        
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename={filename_prefix}.pdf'
        return response
    except Exception as e:
        print(f"WEASYPRINT ERROR: {e}")
        flash(f"An error occurred while generating the PDF: {str(e)}", "danger")
        return redirect(request.referrer or url_for('dashboard'))

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated: return login_manager.unauthorized()
            if current_user.role not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def perform_qc_check(transaction, batch_id, work_order_id):
    """
    Vérifie les résultats QC d'un lot, enregistre les échecs dans QcAlerts
    et retourne True si tous les contrôles sont passés, False sinon.
    Utilise une connexion transactionnelle existante.
    """
    all_passed = True
    
    # ÉTAPE 1: CONTRÔLE DES BLANCS
    blank_check_q = text("""
        SELECT s.SampleID, qr.ElementID, e.ElementSymbol, qr.ResultValue, bcl.ControlLimit
        FROM QcResults qr
        JOIN Samples s ON qr.SampleID = s.SampleID
        JOIN Elements e ON qr.ElementID = e.ElementID
        JOIN BlankControlLimits bcl ON qr.ElementID = bcl.ElementID
        WHERE s.BatchID = :bid AND s.Category = 'Blank' AND qr.ResultValue > bcl.ControlLimit
    """)
    failed_blanks = conn.execute(blank_check_q, {'bid': batch_id}).fetchall()

    for blank in failed_blanks:
        all_passed = False
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'Blank > Limit', :mv, :cl, 'high')
        """), {'bid': batch_id, 'sid': blank.SampleID, 'eid': blank.ElementID, 'mv': blank.ResultValue, 'cl': blank.ControlLimit})

    # ÉTAPE 2: CONTRÔLE DES STANDARDS (ÉCHECS Z-SCORE/LIMITES)
    standard_check_q = text("""
        SELECT s.SampleID, qr.ElementID, e.ElementSymbol, qr.ResultValue, cl.ExpectedValue, cl.ControlLimit
        FROM QcResults qr
        JOIN Samples s ON qr.SampleID = s.SampleID
        JOIN Elements e ON qr.ElementID = e.ElementID
        JOIN ControlLimits cl ON s.StandardID = cl.StandardID AND qr.ElementID = cl.ElementID
        WHERE s.BatchID = :bid AND s.Category = 'Standard' AND ABS(qr.ResultValue - cl.ExpectedValue) > cl.ControlLimit
    """)
    failed_standards = conn.execute(standard_check_q, {'bid': batch_id}).fetchall()
    
    for std in failed_standards:
        all_passed = False
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ExpectedValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'Standard Out of Control Limit', :mv, :ev, :cl, 'high')
        """), {'bid': batch_id, 'sid': std.SampleID, 'eid': std.ElementID, 'mv': std.ResultValue, 'ev': std.ExpectedValue, 'cl': std.ControlLimit})

    # ÉTAPE 3: CONTRÔLE DES DUPLICATAS (RPD)
    # Note : Cette requête est complexe et suppose un seul RPD max par méthode liée au lot.
    duplicate_check_q = text("""
        WITH OriginalResults AS (
            SELECT r.ElementID, r.ResultValue, s.DuplicateOfSampleID as DupSampleID
            FROM Results r JOIN Samples s ON r.SampleID = s.SampleID WHERE s.DuplicateOfSampleID IS NOT NULL AND s.BatchID = :bid
        ), DupResults AS (
            SELECT qr.ElementID, qr.ResultValue, s.SampleID as DupSampleID
            FROM QcResults qr JOIN Samples s ON qr.SampleID = s.SampleID WHERE s.Category = 'Duplicate' AND s.BatchID = :bid
        )
        SELECT o.DupSampleID, o.ElementID, o.ResultValue as OrigValue, d.ResultValue as DupValue, m.MaxRpdForDuplicates
        FROM OriginalResults o JOIN DupResults d ON o.DupSampleID = d.DupSampleID AND o.ElementID = d.ElementID
        JOIN Methods m ON m.MethodID IN (SELECT MethodID FROM WorkOrderMethods WHERE WorkOrderID = :woid)
        WHERE m.MaxRpdForDuplicates IS NOT NULL 
          AND (ABS(o.ResultValue - d.ResultValue) / NULLIF((o.ResultValue + d.ResultValue) / 2, 0) * 100) > m.MaxRpdForDuplicates
    """)
    failed_duplicates = conn.execute(duplicate_check_q, {'bid': batch_id, 'woid': work_order_id}).fetchall()

    for dup in failed_duplicates:
        all_passed = False
        rpd = (abs(dup.OrigValue - dup.DupValue) / ((dup.OrigValue + dup.DupValue) / 2)) * 100
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'RPD > Limit', :mv, :cl, 'medium')
        """), {'bid': batch_id, 'sid': dup.DupSampleID, 'eid': dup.ElementID, 'mv': rpd, 'cl': dup.MaxRpdForDuplicates})
        
    return all_passed

def get_setting(setting_name, default_value=None):
    conn = get_db_connection()
    if not conn: return default_value
    try:
        result = conn.execute(text("SELECT SettingValue FROM AppSettings WHERE SettingName = :name"), {'name': setting_name}).scalar_one_or_none()
        return result if result is not None else default_value
    finally:
        if conn: conn.close()

# --- Login Manager & User Class ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role='admin'): # Rôle par défaut ajouté ici
        self.id, self.username, self.role = id, username, role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn: return None
    try:
        # MODIFIÉ : La colonne 'Role' a été retirée de la requête
        user_data = conn.execute(text("SELECT UserID, Username FROM Users WHERE UserID = :id"), {'id': user_id}).fetchone()
        # MODIFIÉ : Le rôle est maintenant assigné manuellement
        if user_data: return User(id=user_data[0], username=user_data[1]) 
        return None
    finally:
        if conn: conn.close()

# --- Core Routes (ALL UPDATED FOR CONNECTION POOLING) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", "danger")
            return render_template('login.html')
        try:
            user_data = conn.execute(text("SELECT UserID, Username, PasswordHash FROM Users WHERE Username = :username"), {'username': username}).fetchone()
            if user_data and check_password_hash(user_data[2], password):
                # MODIFIÉ : Le rôle est maintenant assigné manuellement
                user_obj = User(id=user_data[0], username=user_data[1])
                login_user(user_obj)
            else:
                flash("Invalid username or password.", "danger")
        finally:
            if conn: conn.close()
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('dashboard.html', kpi={})
    
    kpi = {}
    try:
        kpi['received'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'Received' AND Location = 'Reception'")).scalar()
        kpi['in_prep'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Location = 'Mechanical Prep Unit'")).scalar()
        kpi['awaiting_analysis'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'Awaiting Analysis'")).scalar()
        kpi['qc_failed'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'QC Failed'")).scalar()
        kpi['reporting'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Location = 'Reporting' AND (CertificateStatus IS NULL OR CertificateStatus = 'Rejected')")).scalar()
        kpi['approved'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE CertificateStatus = 'Approved' AND Status <> 'Archived'")).scalar()
    except Exception as e:
        print(f"Dashboard KPI Error: {e}")
        flash(f"An error occurred while loading dashboard data: {e}", "danger")
        kpi = {} # Reset on error
    finally:
        if conn: conn.close()
        
    return render_template('dashboard.html', kpi=kpi)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        conn = get_db_connection()
        if not conn:
             flash("Database error", "danger")
             return redirect(url_for('profile'))
        try:
            with conn.begin() as transaction:
                old_password, new_password, confirm_password = request.form.get('old_password'), request.form.get('new_password'), request.form.get('confirm_password')
                if not all([old_password, new_password, confirm_password]):
                    flash("All password fields are required.", "warning")
                    return redirect(url_for('profile'))
                if new_password != confirm_password:
                    flash("New password and confirmation do not match.", "danger")
                    return redirect(url_for('profile'))
                
                user_data = conn.execute(text("SELECT PasswordHash FROM Users WHERE UserID = :id"), {'id': current_user.id}).fetchone()
                if not user_data or not check_password_hash(user_data[0], old_password):
                    flash("Incorrect old password.", "danger")
                    return redirect(url_for('profile'))

                new_password_hash = generate_password_hash(new_password)
                conn.execute(text("UPDATE Users SET PasswordHash = :hash WHERE UserID = :id"), {'hash': new_password_hash, 'id': current_user.id})
            flash("Your password has been updated successfully! Please log in again.", "success")
            logout_user()
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('profile'))
        finally:
            if conn: conn.close()
    return render_template('profile.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def settings():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                items_per_page = request.form.get('items_per_page')
                conn.execute(text("UPDATE AppSettings SET SettingValue = :val WHERE SettingName = 'ItemsPerPage'"), {'val': items_per_page})
            flash("Settings updated successfully!", "success")
            return redirect(url_for('settings'))
            
        settings_data = {row[0]: row[1] for row in conn.execute(text("SELECT SettingName, SettingValue FROM AppSettings")).fetchall()}
    except Exception as e:
        flash(f"A critical error occurred: {str(e)}", "danger")
        settings_data = {}
    finally:
        if conn: conn.close()
        
    return render_template('settings.html', settings=settings_data)

@app.route('/detailed_reception', methods=['GET', 'POST'])
@login_required
def detailed_reception():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))

    try:
        if request.method == 'POST':
            # --- Use a transaction for the entire POST operation ---
            with conn.begin() as transaction:
                # --- PHASE 1: GATHER ALL FORM DATA ---
                client_id = request.form.get('client_id')
                batch_code = request.form.get('batch_code')
                reception_date = request.form.get('reception_date')
                sample_type = request.form.get('sample_type')
                selected_method_ids = request.form.getlist('method_ids')
                entry_mode = request.form.get('entry_mode')
                payment_mode = request.form.get('payment_mode')
                return_samples = request.form.get('return_samples')
                prep_deadline = request.form.get('prep_deadline') or None
                analysis_deadline = request.form.get('analysis_deadline') or None
                quantity_conformity = request.form.get('quantity_conformity')
                packaging_conformity = request.form.get('packaging_conformity')
                technical_feasibility = request.form.get('technical_feasibility')
                service_status = request.form.get('service_status')
                rejection_reason = request.form.get('rejection_reason')

                # --- VALIDATION ---
                if not all([client_id, batch_code, reception_date]):
                    flash("Client, Batch Code, and Reception Date are required.", "danger")
                    return redirect(url_for('detailed_reception'))
                
                existing_batch = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE BatchCode = :code"), {'code': batch_code}).scalar()
                if existing_batch > 0:
                    flash(f"Error: Batch Code '{batch_code}' already exists.", "danger")
                    return redirect(url_for('detailed_reception'))

                # --- PHASE 2: PROCESS SAMPLES ---
                standards_map = {std.StandardName: std.StandardID for std in conn.execute(text("SELECT StandardID, StandardName FROM QcStandards")).fetchall()}
                samples_to_insert = []
                if entry_mode == 'file' and 'sample_file' in request.files and request.files['sample_file'].filename != '':
                    file = request.files['sample_file']
                    df = pd.read_excel(io.BytesIO(file.read()), dtype={'ClientSampleID': str})
                    df.rename(columns=lambda x: x.strip(), inplace=True)
                    for _, row in df.iterrows():
                        category = row.get('Category', 'Client Sample').strip()
                        standard_id = standards_map.get(row.get('StandardName')) if category == 'Standard' else None
                        weight = row.get('Weight')
                        weight_value = float(weight) if pd.notna(weight) else None
                        samples_to_insert.append({"ClientSampleID": row['ClientSampleID'], "SampleType": row.get('SampleType', sample_type), "Weight": weight_value, "Category": category, "StandardID": standard_id, "DuplicateOf": row.get('DuplicateOf')})
                elif entry_mode == 'manual':
                    row_index = 1
                    while f'manual_sample_id_{row_index}' in request.form:
                        sample_id = request.form.get(f'manual_sample_id_{row_index}')
                        if sample_id:
                            category = request.form.get(f'manual_sample_category_{row_index}')
                            standard_id = request.form.get(f'manual_standard_id_{row_index}') if category == 'Standard' else None
                            weight_str = request.form.get(f'manual_sample_weight_{row_index}')
                            weight_value = float(weight_str) if weight_str else None
                            samples_to_insert.append({"ClientSampleID": sample_id, "SampleType": request.form.get(f'manual_sample_type_{row_index}'), "Weight": weight_value, "Category": category, "StandardID": standard_id, "DuplicateOf": request.form.get(f'manual_duplicate_of_{row_index}')})
                        row_index += 1
                
                if not samples_to_insert:
                    flash("No samples were provided. Please upload a file or enter them manually.", "warning")
                    return redirect(url_for('detailed_reception'))

                # --- PHASE 3: DATABASE OPERATIONS ---
                # 1. Create Batch and get ID
                batch_insert_q = text("INSERT INTO SampleBatches (BatchCode, ClientID, DateReceived, Status, Location) OUTPUT INSERTED.BatchID VALUES (:code, :cid, :date, 'Received', 'Reception')")
                batch_id = conn.execute(batch_insert_q, {'code': batch_code, 'cid': client_id, 'date': reception_date}).scalar()

                # 2. Create WorkOrderDetails
                details_insert_q = text("INSERT INTO WorkOrderDetails (BatchID, SampleType, PaymentMode, ReturnSamples, PrepDeadline, AnalysisDeadline, QuantityConformity, PackagingConformity, TechnicalFeasibility, ServiceStatus, RejectionReason) VALUES (:bid, :st, :pm, :rs, :pd, :ad, :qc, :pc, :tf, :ss, :rr)")
                conn.execute(details_insert_q, {'bid': batch_id, 'st': sample_type, 'pm': payment_mode, 'rs': return_samples, 'pd': prep_deadline, 'ad': analysis_deadline, 'qc': quantity_conformity, 'pc': packaging_conformity, 'tf': technical_feasibility, 'ss': service_status, 'rr': rejection_reason})

                # 3. Create WorkOrder and get ID
                wo_insert_q = text("INSERT INTO WorkOrders (BatchID, Status) OUTPUT INSERTED.WorkOrderID VALUES (:bid, 'Pending')")
                work_order_id = conn.execute(wo_insert_q, {'bid': batch_id}).scalar()

                # 4. Link Methods
                if selected_method_ids:
                    method_data = [{'woid': work_order_id, 'mid': method_id} for method_id in selected_method_ids]
                    conn.execute(text("INSERT INTO WorkOrderMethods (WorkOrderID, MethodID) VALUES (:woid, :mid)"), method_data)
                
                # 5. Insert non-duplicate samples
                non_dup_samples = [s for s in samples_to_insert if s['Category'] != 'Duplicate']
                if non_dup_samples:
                    non_dup_data = [{'bid': batch_id, 'csid': s['ClientSampleID'], 'st': s['SampleType'], 'w': s['Weight'], 'cat': s['Category'], 'sid': s['StandardID']} for s in non_dup_samples]
                    conn.execute(text("INSERT INTO Samples (BatchID, ClientSampleID, SampleType, Weight, Category, StandardID) VALUES (:bid, :csid, :st, :w, :cat, :sid)"), non_dup_data)

                # 6. Insert duplicate samples
                sample_id_map_q = text("SELECT ClientSampleID, SampleID FROM Samples WHERE BatchID = :bid")
                sample_id_map = {row.ClientSampleID: row.SampleID for row in conn.execute(sample_id_map_q, {'bid': batch_id}).fetchall()}
                
                dup_samples = [s for s in samples_to_insert if s['Category'] == 'Duplicate']
                if dup_samples:
                    dup_data = []
                    for dup in dup_samples:
                        original_id = sample_id_map.get(str(dup['DuplicateOf']).strip())
                        dup_data.append({'bid': batch_id, 'csid': dup['ClientSampleID'], 'st': dup['SampleType'], 'w': dup['Weight'], 'cat': 'Duplicate', 'd_of': original_id})
                    conn.execute(text("INSERT INTO Samples (BatchID, ClientSampleID, SampleType, Weight, Category, DuplicateOfSampleID) VALUES (:bid, :csid, :st, :w, :cat, :d_of)"), dup_data)

            # --- END OF TRANSACTION ---
            log_action(conn, batch_id, f"Detailed batch registered with {len(samples_to_insert)} samples.")
            flash(f"Demande de prestation '{batch_code}' enregistrée avec succès!", "success")
            return redirect(url_for('success_page', batch_id=batch_id))

        # --- GET Request Logic ---
        today_date = datetime.now().strftime('%Y-%m-%d')
        clients = conn.execute(text("SELECT ClientID, ClientName FROM Clients ORDER BY ClientName")).fetchall()
        sample_types = conn.execute(text("SELECT TypeName FROM SampleTypes ORDER BY TypeName")).fetchall()
        service_groups = conn.execute(text("SELECT GroupID, GroupName FROM ServiceGroups ORDER BY GroupName")).fetchall()
        methods = conn.execute(text("SELECT MethodID, MethodName, GroupID FROM Methods ORDER BY MethodName")).fetchall()
        qc_standards = conn.execute(text("SELECT StandardID, StandardName FROM QcStandards ORDER BY StandardName")).fetchall()
        payment_modes = ['Chèque', 'Versement', 'En espèce', 'A la charge de l’ANARPAM']
        return_options = ['OUI', 'NON', 'Rejet', 'Echantillon double']
        return render_template('detailed_reception.html', clients=clients, today_date=today_date, sample_types=sample_types, service_groups=service_groups, methods=methods, qc_standards=qc_standards, payment_modes=payment_modes, return_options=return_options)

    except Exception as e:
        flash(f"An error occurred on the reception page: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('reception_queue'))
    finally:
        if conn: conn.close() # Returns connection to the pool

@app.route('/qc_failed/<int:batch_id>')
@login_required
@role_required('admin', 'analyst')
def qc_failed(batch_id):
    """
    Displays a rich QC Failure page with details and actions.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('analysis_queue'))
        
    try:
        batch = conn.execute(text("SELECT BatchID, BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
        # Safely load the warnings passed in the URL
        warnings_json = request.args.get('warnings', '[]')
        warnings = json.loads(warnings_json)
    except Exception as e:
        flash(f"An error occurred loading the QC failure page: {e}", "danger")
        return redirect(url_for('analysis_queue'))
    finally:
        if conn: conn.close()
        
    return render_template('qc_failed.html', batch=batch, warnings=warnings)

@app.route('/reception_queue')
@login_required
def reception_queue():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('reception_queue.html', batches=[])
    try:
        query = text("SELECT b.BatchID, b.BatchCode, c.ClientName, b.Status, b.DateReceived FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE b.Location = 'Reception' AND b.Status <> 'Archived' ORDER BY b.DateReceived DESC;")
        batches = conn.execute(query).fetchall()
    except Exception as e:
        flash(f"An error occurred while fetching the reception queue: {e}", "danger")
        batches = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return render_template('reception_queue.html', batches=batches)

@app.route('/dispatch_batch/<int:batch_id>', methods=['POST'])
@login_required
def dispatch_batch(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('reception_queue'))
    try:
        with conn.begin() as transaction:
            wo_id_q = text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id")
            work_order_id = conn.execute(wo_id_q, {'id': batch_id}).scalar_one()
            
            req_prep_q = text("SELECT m.RequiresPrep FROM Methods m JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID WHERE wom.WorkOrderID = :wo_id")
            methods_req_prep = [row[0] for row in conn.execute(req_prep_q, {'wo_id': work_order_id}).fetchall()]
            
            new_location = "Mechanical Prep Unit" if any(methods_req_prep) else "Chemical Analysis Unit"
            
            update_q = text("UPDATE SampleBatches SET Location = :loc WHERE BatchID = :id")
            conn.execute(update_q, {'loc': new_location, 'id': batch_id})
        
        log_action(batch_id, f"Batch dispatched to {new_location}")
        flash(f"Batch has been dispatched to {new_location}.", "success")
    except Exception as e:
        flash(f"An error occurred during dispatch: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('reception_queue'))

@app.route('/delete_batch/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_batch(batch_id):
    original_location_url = url_for('reception_queue')
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(request.referrer or url_for('dashboard'))
    try:
        with conn.begin() as transaction:
            loc_row = conn.execute(text("SELECT Location FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
            if loc_row:
                if 'Prep' in loc_row[0]: original_location_url = url_for('prep_queue')
                elif 'Analysis' in loc_row[0]: original_location_url = url_for('analysis_queue')

            wo_id_row = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).fetchone()
            if wo_id_row:
                conn.execute(text("DELETE FROM BatchPrepLog WHERE BatchID = :id"), {'id': batch_id})
                conn.execute(text("DELETE FROM WorkOrderMethods WHERE WorkOrderID = :wo_id"), {'wo_id': wo_id_row[0]})
                conn.execute(text("DELETE FROM WorkOrders WHERE WorkOrderID = :wo_id"), {'wo_id': wo_id_row[0]})
            
            conn.execute(text("DELETE FROM WorkOrderDetails WHERE BatchID = :id"), {'id': batch_id})
            conn.execute(text("DELETE FROM AuditLog WHERE BatchID = :id"), {'id': batch_id})
            
            sample_ids = [row[0] for row in conn.execute(text("SELECT SampleID FROM Samples WHERE BatchID = :id"), {'id': batch_id}).fetchall()]
            if sample_ids:
                # Prépare les requêtes pour gérer correctement la clause IN
                stmt_results = text("DELETE FROM Results WHERE SampleID IN :ids").bindparams(
                    bindparam('ids', expanding=True)
                )
                stmt_qc_results = text("DELETE FROM QcResults WHERE SampleID IN :ids").bindparams(
                bindparam('ids', expanding=True)
                )
    
                # Exécute les requêtes avec la liste d'IDs (sans la convertir en tuple)
                conn.execute(stmt_results, {'ids': sample_ids})
                conn.execute(stmt_qc_results, {'ids': sample_ids})
            
            conn.execute(text("DELETE FROM Samples WHERE BatchID = :id"), {'id': batch_id})
            conn.execute(text("DELETE FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id})
        flash("Batch deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred while deleting the batch: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    
    return redirect(original_location_url)

@app.route('/success/<int:batch_id>')
@login_required
def success_page(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))
    try:
        batch = conn.execute(text("SELECT BatchID, BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
        if not batch:
            flash("Batch not found.", "warning")
            return redirect(url_for('reception_queue'))
        return render_template('success.html', batch=batch)
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        if conn: conn.close()

@app.route('/prep_queue')
@login_required
@role_required('admin', 'technician')
def prep_queue():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('prep_queue.html', batches=[], total_pages=1, current_page=1)
    
    batches, total_pages = [], 1
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    try:
        base_query = "FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE b.Location = 'Mechanical Prep Unit' AND b.Status <> 'Archived'"
        params = {}
        if search_term:
            base_query += " AND (b.BatchCode LIKE :search OR c.ClientName LIKE :search)"
            params['search'] = f'%{search_term}%'
        if start_date:
            base_query += " AND b.DateReceived >= :start_date"
            params['start_date'] = start_date
        if end_date:
            base_query += " AND b.DateReceived <= :end_date"
            params['end_date'] = end_date
            
        count_query = text(f"SELECT COUNT(*) {base_query}")
        total_batches = conn.execute(count_query, params).scalar()
        
        PER_PAGE = int(get_setting('ItemsPerPage', 20))
        total_pages = math.ceil(total_batches / PER_PAGE) if total_batches > 0 else 1
        offset = (page - 1) * PER_PAGE
        params['offset'] = offset
        params['per_page'] = PER_PAGE
        
        data_query = text(f"SELECT b.BatchID, b.BatchCode, c.ClientName, b.Status {base_query} ORDER BY b.DateReceived DESC OFFSET :offset ROWS FETCH NEXT :per_page ROWS ONLY")
        batches = conn.execute(data_query, params).fetchall()
    except Exception as e:
        flash(f"An error occurred while fetching the preparation queue: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return render_template('prep_queue.html', batches=batches, search_term=search_term, start_date=start_date, end_date=end_date, current_page=page, total_pages=total_pages)        

# In C:\anarlab\app.py, replace the prep_batch function

@app.route('/prep_batch/<int:batch_id>')
@login_required
@role_required('admin', 'technician')
def prep_batch(batch_id):
    """
    Loads all necessary data for the batch preparation screen.
    This includes batch/client info, sample lists, required prep methods,
    available consumables, and already linked consumables.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_queue'))
    
    try:
        # 1. Fetch core batch and client information
        batch = conn.execute(text("SELECT * FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
        client = conn.execute(text("SELECT * FROM Clients WHERE ClientID = :id"), {'id': batch.ClientID}).fetchone()
        
        # 2. Fetch the list of samples in this batch
        samples = conn.execute(text("SELECT SampleID, ClientSampleID, SampleType, Weight, WeightFinal, Category FROM Samples s WHERE s.BatchID = :id ORDER BY s.SampleID"), {'id': batch_id}).fetchall()
        
        # 3. Fetch the specific preparation methods required for this work order
        prep_methods_q = text("""
            SELECT m.MethodName 
            FROM Methods m
            JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID
            JOIN WorkOrders wo ON wom.WorkOrderID = wo.WorkOrderID
            WHERE wo.BatchID = :id AND m.RequiresPrep = 1
        """)
        prep_methods = conn.execute(prep_methods_q, {'id': batch_id}).fetchall()

        # 4. Fetch available, unexpired consumables for the selection form
        consumables_q = text("""
            SELECT cs.StockID, ct.TypeName, cs.LotNumber 
            FROM ConsumableStock cs
            JOIN ConsumableTypes ct ON cs.ConsumableTypeID = ct.ConsumableTypeID
            WHERE cs.Quantity > 0 AND (cs.ExpiryDate IS NULL OR cs.ExpiryDate >= GETDATE())
            ORDER BY ct.TypeName
        """)
        available_consumables = conn.execute(consumables_q).fetchall()

        # 5. Fetch IDs of consumables already linked to this batch to pre-check the boxes
        linked_consumables_q = text("SELECT StockID FROM BatchConsumableUsage WHERE BatchID = :id")
        linked_consumable_ids = [row[0] for row in conn.execute(linked_consumables_q, {'id': batch_id}).fetchall()]

        # 6. Render the template, passing all the fetched data
        return render_template('prep_batch.html', 
                               batch=batch, 
                               client=client, 
                               samples=samples, 
                               prep_methods=prep_methods,
                               available_consumables=available_consumables,
                               linked_consumable_ids=linked_consumable_ids)
    
    except Exception as e:
        flash(f"An error occurred while fetching prep batch details: {e}", "danger")
        traceback.print_exc()
        # This is the line that was corrected
        return redirect(url_for('prep_queue'))
    finally:
        if conn:
            conn.close()

@app.route('/analysis_queue')
@login_required
@role_required('admin', 'analyst')
def analysis_queue():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('analysis_queue.html', batches=[], total_pages=1, current_page=1)
        
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    
    try:
        base_query = "FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE b.Location = 'Chemical Analysis Unit' AND b.Status <> 'Archived'"
        params = {}
        
        if search_term:
            base_query += " AND (b.BatchCode LIKE :search OR c.ClientName LIKE :search)"
            params['search'] = f'%{search_term}%'
        if start_date:
            base_query += " AND b.DateReceived >= :start_date"
            params['start_date'] = start_date
        if end_date:
            base_query += " AND b.DateReceived <= :end_date"
            params['end_date'] = end_date
            
        count_query = text(f"SELECT COUNT(*) {base_query}")
        total_batches = conn.execute(count_query, params).scalar_one()
        
        PER_PAGE = int(get_setting('ItemsPerPage', 20))
        total_pages = math.ceil(total_batches / PER_PAGE) if total_batches > 0 else 1
        offset = (page - 1) * PER_PAGE
        params['offset'] = offset
        params['per_page'] = PER_PAGE
        
        data_query = text(f"SELECT b.BatchID, b.BatchCode, c.ClientName, b.Status {base_query} ORDER BY b.DateReceived DESC OFFSET :offset ROWS FETCH NEXT :per_page ROWS ONLY")
        batches = conn.execute(data_query, params).fetchall()
        
    except Exception as e:
        flash(f"An error occurred while fetching the analysis queue: {e}", "danger")
        traceback.print_exc()
        batches, total_pages = [], 1
    finally:
        if conn: conn.close()
        
    return render_template('analysis_queue.html', batches=batches, search_term=search_term, start_date=start_date, end_date=end_date, current_page=page, total_pages=total_pages)

@app.route('/enter_results/<int:batch_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'analyst')
def enter_results(batch_id):
    
    # ---- Logique pour le POST (Importation) ----
    if request.method == 'POST':
        conn = get_db_connection()
        if not conn:
            flash("Erreur de connexion a la BDD.", "danger")
            return redirect(url_for('analysis_queue'))
        try:
            with conn.begin() as transaction:
                wo_id_q = text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id")
                work_order_id = conn.execute(wo_id_q, {'id': batch_id}).scalar_one()

                instrument_id = request.form.get('instrument_id')
                uploaded_file = request.files.get('results_file')
                if not instrument_id or not uploaded_file:
                    flash("Instrument et fichier sont requis.", "warning")
                    return redirect(url_for('enter_results', batch_id=batch_id))

                df = pd.read_excel(io.BytesIO(uploaded_file.read()), dtype={'ClientSampleID': str})
                df.rename(columns=lambda x: x.strip(), inplace=True)
                
                if 'AnalysisWeight' not in df.columns:
                    flash("Avertissement : La colonne 'AnalysisWeight' est absente du fichier Excel. Les poids d'analyse ne seront pas importés.", "warning")

                elements_map = {row.ElementSymbol: row.ElementID for row in conn.execute(text("SELECT ElementID, ElementSymbol FROM Elements")).fetchall()}
                samples_in_batch = {s.ClientSampleID.strip(): (s.SampleID, s.Category) for s in conn.execute(text("SELECT SampleID, ClientSampleID, Category FROM Samples WHERE BatchID = :id"), {'id': batch_id}).fetchall()}
                required_symbols = {row.ElementSymbol for row in conn.execute(text("SELECT DISTINCT e.ElementSymbol FROM Elements e JOIN MethodElements me ON e.ElementID = me.ElementID JOIN WorkOrderMethods wom ON me.MethodID = wom.MethodID WHERE wom.WorkOrderID = :woid"), {'woid': work_order_id}).fetchall()}

                client_results, qc_results = [], []
                for _, row in df.iterrows():
                    sample_info = samples_in_batch.get(str(row['ClientSampleID']).strip())
                    if sample_info:
                        sample_id, category = sample_info
                        analysis_weight = row.get('AnalysisWeight')
                        analysis_weight_val = float(analysis_weight) if pd.notna(analysis_weight) else None
                        for symbol in required_symbols:
                            if symbol in row and pd.notna(row[symbol]):
                                element_id = elements_map.get(symbol)
                                if element_id:
                                    data = {'sid': sample_id, 'eid': element_id, 'val': float(row[symbol]), 'inst': instrument_id, 'aw': analysis_weight_val}
                                    if category == 'Client Sample':
                                        client_results.append(data)
                                    else:
                                        qc_results.append(data)
                
                if not client_results and not qc_results:
                    # On ne fait aucune opération sur la BDD et on retourne une erreur
                    flash("ERREUR : Aucun échantillon correspondant n'a été trouvé dans le fichier Excel importé. Aucune modification n'a été apportée.", "danger")
                    return redirect(url_for('enter_results', batch_id=batch_id))
                
                if 'AnalysisWeight' not in df.columns:
                    flash("Avertissement : La colonne 'AnalysisWeight' est absente du fichier Excel. Les poids d'analyse n'ont pas été importés.", "warning")
                
                all_sids = [s[0] for s in samples_in_batch.values()]
                
                all_sids = [s[0] for s in samples_in_batch.values()]
                if all_sids:
                    conn.execute(text("DELETE FROM Results WHERE SampleID IN :ids").bindparams(bindparam('ids', expanding=True)), {'ids': all_sids})
                    conn.execute(text("DELETE FROM QcResults WHERE SampleID IN :ids").bindparams(bindparam('ids', expanding=True)), {'ids': all_sids})
                
                if client_results:
                    conn.execute(text("INSERT INTO Results (SampleID, ElementID, ResultValue, Unit, InstrumentID, AnalysisDate, AnalysisWeight) VALUES (:sid, :eid, :val, 'ppm', :inst, GETDATE(), :aw)"), client_results)
                if qc_results:
                    conn.execute(text("INSERT INTO QcResults (SampleID, ElementID, ResultValue, Unit, InstrumentID, AnalysisDate, AnalysisWeight) VALUES (:sid, :eid, :val, 'ppm', :inst, GETDATE(), :aw)"), qc_results)
                
                conn.execute(text("DELETE FROM QcAlerts WHERE BatchID = :bid"), {'bid': batch_id})
                qc_passed = perform_qc_check(conn, batch_id, work_order_id)
                
                new_status = "Analysis Complete" if qc_passed else "QC Failed"
                new_location = "Reporting" if qc_passed else "Chemical Analysis Unit"
                
                conn.execute(text("UPDATE SampleBatches SET Status = :status, Location = :loc WHERE BatchID = :id"), {'status': new_status, 'loc': new_location, 'id': batch_id})
            
            flash("Importation terminée.", "success" if qc_passed else "warning")
            if not qc_passed:
                return redirect(url_for('qc_failed', batch_id=batch_id))
            else:
                return redirect(url_for('analysis_queue'))
        
        except Exception as e:
            flash(f"Une erreur critique est survenue durant l'importation: {e}", "danger")
            traceback.print_exc()
            return redirect(url_for('analysis_queue'))
        finally:
            if conn: conn.close()
    
    # ---- Logique pour le GET (Affichage de la page) ----
    conn = get_db_connection()
    if not conn:
        flash("Erreur de connexion a la BDD.", "danger")
        return redirect(url_for('analysis_queue'))
    try:
        wo_id_q = text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id")
        work_order_id = conn.execute(wo_id_q, {'id': batch_id}).scalar_one_or_none()
        if not work_order_id:
            flash(f"Impossible de trouver l'ordre de travail pour le lot ID {batch_id}.", "danger")
            return redirect(url_for('analysis_queue'))

        batch = conn.execute(text("SELECT * FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
        client = conn.execute(text("SELECT * FROM Clients WHERE ClientID = :cid"), {'cid': batch.ClientID}).fetchone()
        elements = conn.execute(text("SELECT DISTINCT e.ElementSymbol, e.ElementName FROM Elements e JOIN MethodElements me ON e.ElementID = me.ElementID JOIN WorkOrderMethods wom ON me.MethodID = wom.MethodID WHERE wom.WorkOrderID = :woid"), {'woid': work_order_id}).fetchall()
        instruments = conn.execute(text("SELECT InstrumentID, InstrumentName, InstrumentCode FROM Instruments WHERE Status = 'Opérationnel' ORDER BY InstrumentName")).fetchall()
        client_samples = conn.execute(text("SELECT ClientSampleID, SampleType, Category FROM Samples WHERE BatchID = :id AND Category = 'Client Sample' ORDER BY SampleID"), {'id': batch_id}).fetchall()
        qc_samples = conn.execute(text("SELECT ClientSampleID, Category FROM Samples WHERE BatchID = :id AND Category <> 'Client Sample' ORDER BY SampleID"), {'id': batch_id}).fetchall()
        
        return render_template('results_entry.html', 
                               batch=batch, client=client, elements=elements, 
                               instruments=instruments, client_samples=client_samples, 
                               qc_samples=qc_samples)
    except Exception as e:
        flash(f"Une erreur critique est survenue en chargeant la page: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('analysis_queue'))
    finally:
        if conn: conn.close()

def perform_qc_check(conn, batch_id, work_order_id):
    """
    Vérifie les résultats QC d'un lot, enregistre les échecs dans QcAlerts
    et retourne True si tous les contrôles sont passés, False sinon.
    """
    all_passed = True  # <--- C'EST LA LIGNE QUI MANQUAIT

    # ÉTAPE 1: CONTRÔLE DES BLANCS
    blank_check_q = text("""
        SELECT s.SampleID, qr.ElementID, e.ElementSymbol, qr.ResultValue, bcl.ControlLimit
        FROM QcResults qr
        JOIN Samples s ON qr.SampleID = s.SampleID
        JOIN Elements e ON qr.ElementID = e.ElementID
        JOIN BlankControlLimits bcl ON qr.ElementID = bcl.ElementID
        WHERE s.BatchID = :bid AND s.Category = 'Blank' AND qr.ResultValue > bcl.ControlLimit
    """)
    failed_blanks = conn.execute(blank_check_q, {'bid': batch_id}).fetchall()

    for blank in failed_blanks:
        all_passed = False
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'Blank > Limit', :mv, :cl, 'high')
        """), {'bid': batch_id, 'sid': blank.SampleID, 'eid': blank.ElementID, 'mv': blank.ResultValue, 'cl': blank.ControlLimit})

    # ÉTAPE 2: CONTRÔLE DES STANDARDS (ÉCHECS Z-SCORE/LIMITES)
    standard_check_q = text("""
        SELECT s.SampleID, qr.ElementID, e.ElementSymbol, qr.ResultValue, cl.ExpectedValue, cl.ControlLimit
        FROM QcResults qr
        JOIN Samples s ON qr.SampleID = s.SampleID
        JOIN Elements e ON qr.ElementID = e.ElementID
        JOIN ControlLimits cl ON s.StandardID = cl.StandardID AND qr.ElementID = cl.ElementID
        WHERE s.BatchID = :bid AND s.Category = 'Standard' AND ABS(qr.ResultValue - cl.ExpectedValue) > cl.ControlLimit
    """)
    failed_standards = conn.execute(standard_check_q, {'bid': batch_id}).fetchall()
    
    for std in failed_standards:
        all_passed = False
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ExpectedValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'Standard Out of Control Limit', :mv, :ev, :cl, 'high')
        """), {'bid': batch_id, 'sid': std.SampleID, 'eid': std.ElementID, 'mv': std.ResultValue, 'ev': std.ExpectedValue, 'cl': std.ControlLimit})

    # ÉTAPE 3: CONTRÔLE DES DUPLICATAS (RPD)
    duplicate_check_q = text("""
        WITH OriginalSamples AS (
            SELECT SampleID as OrigSampleID, ClientSampleID
            FROM Samples
            WHERE BatchID = :bid AND Category = 'Client Sample'
        ),
        DuplicatePairs AS (
            SELECT s.SampleID as DupSampleID, s.ClientSampleID as DupClientSampleID, o.OrigSampleID, o.ClientSampleID as OrigClientSampleID
            FROM Samples s
            JOIN OriginalSamples o ON s.DuplicateOfSampleID = o.OrigSampleID
            WHERE s.BatchID = :bid AND s.Category = 'Duplicate'
        ),
        OriginalResults AS (
            SELECT p.DupSampleID, p.DupClientSampleID, p.OrigClientSampleID, r.ElementID, r.ResultValue
            FROM Results r
            JOIN DuplicatePairs p ON r.SampleID = p.OrigSampleID
        ),
        DuplicateResults AS (
            SELECT qr.SampleID as DupSampleID, qr.ElementID, qr.ResultValue
            FROM QcResults qr
            WHERE qr.SampleID IN (SELECT DupSampleID FROM DuplicatePairs)
        )
        SELECT 
            orig.DupClientSampleID, 
            orig.OrigClientSampleID,
            orig.ElementID, 
            e.ElementSymbol,
            orig.ResultValue as OrigValue, 
            dup.ResultValue as DupValue,
            m.MaxRpdForDuplicates
        FROM OriginalResults orig
        JOIN DuplicateResults dup ON orig.DupSampleID = dup.DupSampleID AND orig.ElementID = dup.ElementID
        JOIN Elements e ON orig.ElementID = e.ElementID
        JOIN Methods m ON m.MethodID IN (SELECT MethodID FROM WorkOrderMethods WHERE WorkOrderID = :woid)
        WHERE m.MaxRpdForDuplicates IS NOT NULL AND (ABS(orig.ResultValue - dup.ResultValue) / NULLIF(((orig.ResultValue + dup.ResultValue) / 2.0), 0) * 100.0) > m.MaxRpdForDuplicates
    """)
    failed_duplicates = conn.execute(duplicate_check_q, {'bid': batch_id, 'woid': work_order_id}).fetchall()

    for dup in failed_duplicates:
        all_passed = False
        rpd = (abs(dup.OrigValue - dup.DupValue) / ((dup.OrigValue + dup.DupValue) / 2)) * 100
        conn.execute(text("""
            INSERT INTO QcAlerts (BatchID, SampleID, ElementID, RuleViolated, MeasuredValue, ControlLimit, Severity)
            VALUES (:bid, :sid, :eid, 'RPD > Limit', :mv, :cl, 'medium')
        """), {'bid': batch_id, 'sid': dup.DupSampleID, 'eid': dup.ElementID, 'mv': rpd, 'cl': dup.MaxRpdForDuplicates})
        
    return all_passed

@app.route('/receipt/<int:batch_id>')
@login_required
def receipt_pdf(batch_id):
    conn = get_db_connection()
    if not conn: return "Database error", 500
    try:
        demande_q = text("SELECT b.*, c.ClientName, c.ClientAddress, wd.* FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID LEFT JOIN WorkOrderDetails wd ON b.BatchID = wd.BatchID WHERE b.BatchID = :id")
        demande = conn.execute(demande_q, {'id': batch_id}).fetchone()
        
        wo_id = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).scalar_one()
        
        methods = conn.execute(text("SELECT m.MethodName FROM Methods m JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID WHERE wom.WorkOrderID = :wo_id"), {'wo_id': wo_id}).fetchall()
        samples = conn.execute(text("SELECT ClientSampleID FROM Samples WHERE BatchID = :id"), {'id': batch_id}).fetchall()
        
        html_out = render_template('receipt_template.html', demande=demande, samples=samples, methods=methods)
        return generate_pdf_response(html_out, f'Receipt_{demande.BatchCode}')
    finally:
        if conn: conn.close()

@app.route('/work_order/<int:batch_id>')
@login_required
def work_order_pdf(batch_id):
    conn = get_db_connection()
    if not conn: return "Database error", 500
    try:
        demande_q = text("SELECT b.*, c.ClientName, wd.* FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID LEFT JOIN WorkOrderDetails wd ON b.BatchID = wd.BatchID WHERE b.BatchID = :id")
        demande = conn.execute(demande_q, {'id': batch_id}).fetchone()
        
        wo_id = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).scalar_one()
        
        methods_q = text("SELECT g.GroupName, m.MethodName FROM Methods m JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID JOIN ServiceGroups g ON m.GroupID = g.GroupID WHERE wom.WorkOrderID = :wo_id ORDER BY g.GroupName, m.MethodName")
        methods_by_group = conn.execute(methods_q, {'wo_id': wo_id}).fetchall()
        
        samples = conn.execute(text("SELECT SampleID, ClientSampleID FROM Samples WHERE BatchID = :id"), {'id': batch_id}).fetchall()
        
        grouped_methods = {}
        for group_name, method_name in methods_by_group:
            if group_name not in grouped_methods: grouped_methods[group_name] = []
            grouped_methods[group_name].append(method_name)
            
        html_out = render_template('work_order_template_no_qr.html', demande=demande, samples=samples, grouped_methods=grouped_methods)
        return generate_pdf_response(html_out, f'WorkOrder_{demande.BatchCode}')
    finally:
        if conn: conn.close()

# In app.py, find and REPLACE the qc_failure_report function with this one.

@app.route('/qc_failure_report/<int:batch_id>')
@login_required
@role_required('admin', 'analyst')
def qc_failure_report(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('analysis_queue'))

    try:
        demande = conn.execute(text("SELECT BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()

        # 1. Get all QC results as dictionaries
        qc_results_q = text("""
            SELECT s.ClientSampleID, s.Category, st.StandardName, e.ElementSymbol, qr.ResultValue, qr.ElementID, s.StandardID
            FROM QcResults qr
            JOIN Samples s ON qr.SampleID = s.SampleID
            JOIN Elements e ON qr.ElementID = e.ElementID
            LEFT JOIN QcStandards st ON s.StandardID = st.StandardID
            WHERE s.BatchID = :id AND s.Category <> 'Client Sample'
        """)
        qc_results = conn.execute(qc_results_q, {'id': batch_id}).mappings().fetchall()

        # 2. Get all necessary limits also as dictionaries
        std_limits_q = text("SELECT StandardID, ElementID, ExpectedValue, ControlLimit FROM ControlLimits")
        std_limits_rows = conn.execute(std_limits_q).mappings().fetchall()
        std_limits = {(row['StandardID'], row['ElementID']): row for row in std_limits_rows}

        blank_limits_q = text("SELECT ElementID, ControlLimit FROM BlankControlLimits")
        blank_limits_rows = conn.execute(blank_limits_q).mappings().fetchall()
        blank_limits = {row['ElementID']: row['ControlLimit'] for row in blank_limits_rows}

        # 3. Process the results using dictionary-style access ([])
        processed_results = []
        for qc_row in qc_results:
            row = dict(qc_row)
            row['status'] = "PASS"
            row['expected_display'] = "N/A"

            if row['Category'] == 'Standard' and row['StandardID'] is not None:
                limit = std_limits.get((row['StandardID'], row['ElementID']))
                
                if limit and limit.get('ExpectedValue') is not None and limit.get('ControlLimit') is not None:
                    expected_value = limit['ExpectedValue']
                    control_limit = limit['ControlLimit']
                    row['expected_display'] = f"{expected_value:.2f} ± {control_limit:.2f}"
                    if abs(row['ResultValue'] - expected_value) > control_limit:
                        row['status'] = "FAIL"
            
            elif row['Category'] == 'Blank':
                limit_value = blank_limits.get(row['ElementID'])
                if limit_value is not None:
                    row['expected_display'] = f"< {limit_value:.3f}"
                    if row['ResultValue'] > limit_value:
                        row['status'] = "FAIL"

            processed_results.append(row)

        html_out = render_template('qc_failure_report_template.html',
                                   demande=demande,
                                   qc_results_with_limits=processed_results,
                                   analysis_date=datetime.now().strftime('%Y-%m-%d'))
        return generate_pdf_response(html_out, f'QC_FAIL_{demande.BatchCode}')

    except Exception as e:
        flash(f"An error occurred while generating the QC report: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('analysis_queue'))
    finally:
        if conn:
            conn.close()

@app.route('/generate_certificate/<int:batch_id>')
@login_required
@role_required('admin', 'analyst')
def generate_certificate(batch_id):
    # Étape 1 : Obtenir la connexion
    conn = get_db_connection()
    if not conn:
        flash("Erreur de connexion a la BDD.", "danger")
        return redirect(url_for('reporting_queue'))
    
    try:
        # La transaction implicite commence ici avec la première requête
        batch_q = text("""
            SELECT b.*, c.ClientName, u.Username AS ApprovedBy
            FROM SampleBatches AS b
            JOIN Clients AS c ON b.ClientID = c.ClientID
            LEFT JOIN Users AS u ON b.CertificateApprovedByUserID = u.UserID
            WHERE b.BatchID = :id
        """)
        batch = conn.execute(batch_q, {'id': batch_id}).fetchone()

        if not batch or batch.CertificateStatus != 'Approved':
            flash("Impossible de générer un certificat pour un lot non approuvé.", "warning")
            return redirect(url_for('reporting_queue'))

        client_results_df = pd.read_sql(
            text("""
                SELECT s.ClientSampleID, e.ElementSymbol, r.ResultValue, r.AnalysisWeight 
                FROM Results r 
                JOIN Samples s ON r.SampleID = s.SampleID 
                JOIN Elements e ON r.ElementID = e.ElementID 
                WHERE s.BatchID = :id AND s.Category = 'Client Sample'
            """),
            conn, params={'id': batch_id}
        )
        
        pivoted_client_results = pd.DataFrame()
        elements_in_order = []
        analysis_weights_map = {}

        if not client_results_df.empty:
            pivoted_client_results = client_results_df.pivot_table(
                index='ClientSampleID', columns='ElementSymbol', values='ResultValue'
            ).fillna('-')
            elements_in_order = sorted(pivoted_client_results.columns.tolist())
            weights_df = client_results_df[['ClientSampleID', 'AnalysisWeight']].dropna().drop_duplicates('ClientSampleID')
            analysis_weights_map = pd.Series(weights_df.AnalysisWeight.values, index=weights_df.ClientSampleID).to_dict()

        qc_results_q = text("""
            SELECT s.ClientSampleID, s.Category, e.ElementSymbol, qr.ResultValue, qr.AnalysisWeight
            FROM QcResults qr 
            JOIN Samples s ON qr.SampleID = s.SampleID 
            JOIN Elements e ON qr.ElementID = e.ElementID 
            WHERE s.BatchID = :id 
            ORDER BY s.Category, s.ClientSampleID, e.ElementSymbol
        """)
        qc_results_list = conn.execute(qc_results_q, {'id': batch_id}).fetchall()

        if client_results_df.empty and not qc_results_list:
            flash("Aucun résultat (ni client, ni QC) trouvé pour ce lot.", "warning")
            return redirect(url_for('reporting_queue'))

        # --- CORRECTION APPLIQUÉE ICI ---
        # On effectue notre opération d'écriture (log_action) DANS la transaction existante.
        log_action(conn, batch_id, "Official Certificate PDF with QC Appendix Generated")
        # Puis on valide (commit) explicitement la transaction pour sauvegarder le log.
        conn.commit()
        # --- FIN DE LA CORRECTION ---

        report_date = datetime.now().strftime('%Y-%m-%d')
        
        html_out = render_template('certificate_template.html', 
                                   batch=batch, 
                                   pivoted_results=pivoted_client_results, 
                                   elements_in_order=elements_in_order,
                                   analysis_weights_map=analysis_weights_map,
                                   qc_results=qc_results_list,
                                   report_date=report_date)
                                   
        return generate_pdf_response(html_out, f'Certificate_v{batch.CertificateVersion}_{batch.BatchCode}')

    except Exception as e:
        # En cas d'erreur, il est bon de faire un rollback
        if conn: conn.rollback()
        traceback.print_exc()
        flash(f"Une erreur critique est survenue lors de la génération du PDF : {e}", "danger")
        return redirect(url_for('reporting_queue'))
    finally:
        # Le bloc finally s'assure que la connexion est toujours fermée
        if conn: conn.close()

@app.route('/manage_clients', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_clients():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_clients.html', clients=[])

    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                conn.execute(text("INSERT INTO Clients (ClientName, ContactPerson, ContactEmail, ClientAddress) VALUES (:name, :person, :email, :address)"),
                                  request.form)
            flash(f"Client '{request.form.get('client_name')}' added successfully!", "success")
            return redirect(url_for('manage_clients'))
        
        clients = conn.execute(text("SELECT ClientID, ClientName, ContactPerson, ContactEmail, ClientAddress FROM Clients ORDER BY ClientName")).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        clients = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return render_template('manage_clients.html', clients=clients)

@app.route('/client/edit-form/<int:client_id>')
@login_required
@role_required('admin')
def edit_client_form(client_id):
    conn = get_db_connection()
    if not conn: return "<div class='alert alert-danger'>Database connection error.</div>"
    try:
        client = conn.execute(text("SELECT * FROM Clients WHERE ClientID = :id"), {'id': client_id}).fetchone()
        if not client: return "<div class='alert alert-warning'>Client not found.</div>"
        return render_template('_edit_client_form.html', client=client)
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>"
    finally:
        if conn: conn.close()

@app.route('/client/edit/<int:client_id>', methods=['POST'])
@login_required
@role_required('admin')
def edit_client_post(client_id):
    conn = get_db_connection()
    if not conn: return f"<div class='alert alert-danger'>Database error.</div>", 500
    try:
        with conn.begin() as transaction:
            params = {
                'name': request.form.get('client_name'),
                'person': request.form.get('contact_person'),
                'email': request.form.get('contact_email'),
                'address': request.form.get('client_address'),
                'id': client_id
            }
            conn.execute(text("UPDATE Clients SET ClientName = :name, ContactPerson = :person, ContactEmail = :email, ClientAddress = :address WHERE ClientID = :id"), params)
        
        client = conn.execute(text("SELECT * FROM Clients WHERE ClientID = :id"), {'id': client_id}).fetchone()
        response_headers = {'HX-Trigger': 'closeClientModal'}
        return render_template('_client_table_row.html', client=client), 200, response_headers
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>", 500
    finally:
        if conn: conn.close()

@app.route('/delete_client/<int:client_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_client(client_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_clients'))
    try:
        with conn.begin() as transaction:
            batch_count = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE ClientID = :id"), {'id': client_id}).scalar()
            if batch_count > 0:
                flash("Cannot delete client with existing batches.", "danger")
                return redirect(url_for('manage_clients'))
            
            conn.execute(text("DELETE FROM Clients WHERE ClientID = :id"), {'id': client_id})
        flash("Client deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting client: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_clients'))

@app.route('/manage_methods', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_methods():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                max_rpd = request.form.get('max_rpd')
                params = {
                    'name': request.form.get('method_name'),
                    'code': request.form.get('method_code'),
                    'gid': request.form.get('group_id'),
                    'prep': 1 if request.form.get('requires_prep') else 0,
                    'rpd': max_rpd if max_rpd and max_rpd.strip() != '' else None
                }
                conn.execute(text("INSERT INTO Methods (MethodName, MethodCode, GroupID, RequiresPrep, MaxRpdForDuplicates) VALUES (:name, :code, :gid, :prep, :rpd)"), params)
            flash(f"Method '{request.form.get('method_name')}' added successfully!", "success")
            return redirect(url_for('manage_methods'))
        
        service_groups = conn.execute(text("SELECT GroupID, GroupName FROM ServiceGroups ORDER BY GroupName")).fetchall()
        methods_q = text("SELECT m.MethodID, m.MethodName, m.MethodCode, g.GroupName, m.RequiresPrep, m.MaxRpdForDuplicates FROM Methods m LEFT JOIN ServiceGroups g ON m.GroupID = g.GroupID ORDER BY g.GroupName, m.MethodName")
        methods = conn.execute(methods_q).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        methods, service_groups = [], []
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return render_template('manage_methods.html', methods=methods, service_groups=service_groups)

@app.route('/method/edit-form/<int:method_id>')
@login_required
@role_required('admin')
def edit_method_form(method_id):
    conn = get_db_connection()
    if not conn: return "<div class='alert alert-danger'>Database connection error.</div>"
    try:
        method = conn.execute(text("SELECT * FROM Methods WHERE MethodID = :id"), {'id': method_id}).fetchone()
        service_groups = conn.execute(text("SELECT GroupID, GroupName FROM ServiceGroups ORDER BY GroupName")).fetchall()
        if not method: return "<div class='alert alert-warning'>Method not found.</div>"
        return render_template('edit_method.html', method=method, service_groups=service_groups)
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>"
    finally:
        if conn: conn.close()

@app.route('/method/edit/<int:method_id>', methods=['POST'])
@login_required
@role_required('admin')
def edit_method_post(method_id):
    conn = get_db_connection()
    if not conn: return f"<div class='alert alert-danger'>Database error.</div>", 500
    try:
        with conn.begin() as transaction:
            max_rpd = request.form.get('max_rpd')
            params = {
                'name': request.form.get('method_name'),
                'code': request.form.get('method_code'),
                'gid': request.form.get('group_id'),
                'prep': 1 if request.form.get('requires_prep') else 0,
                'rpd': max_rpd if max_rpd and max_rpd.strip() != '' else None,
                'id': method_id
            }
            conn.execute(text("UPDATE Methods SET MethodName = :name, MethodCode = :code, GroupID = :gid, RequiresPrep = :prep, MaxRpdForDuplicates = :rpd WHERE MethodID = :id"), params)
        
        method_q = text("SELECT m.MethodID, m.MethodName, m.MethodCode, g.GroupName, m.RequiresPrep, m.MaxRpdForDuplicates FROM Methods m LEFT JOIN ServiceGroups g ON m.GroupID = g.GroupID WHERE m.MethodID = :id")
        method = conn.execute(method_q, {'id': method_id}).fetchone()
        
        response_headers = {'HX-Trigger': 'closeMethodModal'}
        return render_template('_method_table_row.html', method=method), 200, response_headers
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>", 500
    finally:
        if conn: conn.close()

@app.route('/delete_method/<int:method_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_method(method_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_methods'))
    try:
        with conn.begin() as transaction:
            # Check for associations before deleting
            usage_count = conn.execute(text("SELECT COUNT(*) FROM WorkOrderMethods WHERE MethodID = :id"), {'id': method_id}).scalar()
            if usage_count > 0:
                flash("Cannot delete this method. It is in use in one or more work orders.", "danger")
                return redirect(url_for('manage_methods'))
            
            # Delete from linking tables first
            conn.execute(text("DELETE FROM MethodElements WHERE MethodID = :id"), {'id': method_id})
            conn.execute(text("DELETE FROM Methods WHERE MethodID = :id"), {'id': method_id})
        flash("Method deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_methods'))

@app.route('/manage_sample_types', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_sample_types():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_sample_types.html', sample_types=[])

    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                type_name = request.form.get('type_name')
                conn.execute(text("INSERT INTO SampleTypes (TypeName) VALUES (:name)"), {'name': type_name})
            flash("Sample Type added successfully!", "success")
            return redirect(url_for('manage_sample_types'))
        
        sample_types = conn.execute(text("SELECT SampleTypeID, TypeName FROM SampleTypes ORDER BY TypeName")).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        sample_types = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return render_template('manage_sample_types.html', sample_types=sample_types)

@app.route('/sample-type/edit-form/<int:type_id>')
@login_required
@role_required('admin')
def edit_sample_type_form(type_id):
    conn = get_db_connection()
    if not conn: return "<div class='alert alert-danger'>Database connection error.</div>"
    try:
        sample_type = conn.execute(text("SELECT * FROM SampleTypes WHERE SampleTypeID = :id"), {'id': type_id}).fetchone()
        return render_template('edit_sample_type.html', sample_type=sample_type)
    finally:
        if conn: conn.close()

@app.route('/sample-type/edit/<int:type_id>', methods=['POST'])
@login_required
@role_required('admin')
def edit_sample_type_post(type_id):
    conn = get_db_connection()
    if not conn: return f"<div class='alert alert-danger'>Database error.</div>", 500
    try:
        with conn.begin() as transaction:
            new_name = request.form.get('type_name')
            conn.execute(text("UPDATE SampleTypes SET TypeName = :name WHERE SampleTypeID = :id"), {'name': new_name, 'id': type_id})
        
        sample_type = conn.execute(text("SELECT * FROM SampleTypes WHERE SampleTypeID = :id"), {'id': type_id}).fetchone()
        response_headers = {'HX-Trigger': 'closeSampleTypeModal'}
        return render_template('_sample_type_table_row.html', type=sample_type), 200, response_headers
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>", 500
    finally:
        if conn: conn.close()

@app.route('/delete_sample_type/<int:type_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_sample_type(type_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_sample_types'))
    try:
        with conn.begin() as transaction:
            conn.execute(text("DELETE FROM SampleTypes WHERE SampleTypeID = :id"), {'id': type_id})
        flash("Sample Type deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_sample_types'))

@app.route('/manage_elements', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_elements():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_elements.html', elements=[])

    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                params = {
                    'symbol': request.form.get('element_symbol').strip(),
                    'name': request.form.get('element_name').strip()
                }
                conn.execute(text("INSERT INTO Elements (ElementSymbol, ElementName) VALUES (:symbol, :name)"), params)
            flash(f"Element '{params['name']} ({params['symbol']})' added successfully!", "success")
            return redirect(url_for('manage_elements'))
        
        elements = conn.execute(text("SELECT ElementID, ElementSymbol, ElementName FROM Elements ORDER BY ElementName")).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        elements = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return render_template('manage_elements.html', elements=elements)

@app.route('/element/edit-form/<int:element_id>')
@login_required
@role_required('admin')
def edit_element_form(element_id):
    conn = get_db_connection()
    if not conn: return "<div class='alert alert-danger'>Database connection error.</div>"
    try:
        element = conn.execute(text("SELECT * FROM Elements WHERE ElementID = :id"), {'id': element_id}).fetchone()
        return render_template('edit_element.html', element=element)
    finally:
        if conn: conn.close()

@app.route('/element/edit/<int:element_id>', methods=['POST'])
@login_required
@role_required('admin')
def edit_element_post(element_id):
    conn = get_db_connection()
    if not conn: return f"<div class='alert alert-danger'>Database error.</div>", 500
    try:
        with conn.begin() as transaction:
            params = {
                'symbol': request.form.get('element_symbol'),
                'name': request.form.get('element_name'),
                'id': element_id
            }
            conn.execute(text("UPDATE Elements SET ElementSymbol = :symbol, ElementName = :name WHERE ElementID = :id"), params)
        
        element = conn.execute(text("SELECT * FROM Elements WHERE ElementID = :id"), {'id': element_id}).fetchone()
        response_headers = {'HX-Trigger': 'closeElementModal'}
        return render_template('_element_table_row.html', element=element), 200, response_headers
    except Exception as e:
        return f"<div class='alert alert-danger'>An error occurred: {e}</div>", 500
    finally:
        if conn: conn.close()

@app.route('/delete_element/<int:element_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_element(element_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_elements'))
    try:
        with conn.begin() as transaction:
            # Check for associations in results tables before deleting
            res_count = conn.execute(text("SELECT COUNT(*) FROM Results WHERE ElementID = :id"), {'id': element_id}).scalar()
            qc_res_count = conn.execute(text("SELECT COUNT(*) FROM QcResults WHERE ElementID = :id"), {'id': element_id}).scalar()
            
            if res_count > 0 or qc_res_count > 0:
                flash("Cannot delete this element. It has been used in results.", "danger")
                return redirect(url_for('manage_elements'))
            
            # Delete from linking tables first
            conn.execute(text("DELETE FROM MethodElements WHERE ElementID = :id"), {'id': element_id})
            conn.execute(text("DELETE FROM ControlLimits WHERE ElementID = :id"), {'id': element_id})
            conn.execute(text("DELETE FROM BlankControlLimits WHERE ElementID = :id"), {'id': element_id})
            conn.execute(text("DELETE FROM Elements WHERE ElementID = :id"), {'id': element_id})
        flash("Element deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_elements'))

@app.route('/manage_method_elements/<int:method_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_method_elements(method_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_methods'))
    
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                selected_element_ids = request.form.getlist('element_ids')
                
                conn.execute(text("DELETE FROM MethodElements WHERE MethodID = :mid"), {'mid': method_id})
                
                if selected_element_ids:
                    insert_data = [{'mid': method_id, 'eid': eid} for eid in selected_element_ids]
                    conn.execute(text("INSERT INTO MethodElements (MethodID, ElementID) VALUES (:mid, :eid)"), insert_data)
            flash("Element links updated successfully!", "success")
            return redirect(url_for('manage_methods'))

        # GET request
        method = conn.execute(text("SELECT MethodID, MethodName FROM Methods WHERE MethodID = :id"), {'id': method_id}).fetchone()
        if not method:
            flash("Method not found.", "danger")
            return redirect(url_for('manage_methods'))
            
        all_elements = conn.execute(text("SELECT ElementID, ElementSymbol, ElementName FROM Elements ORDER BY ElementName")).fetchall()
        linked_elements_q = text("SELECT ElementID FROM MethodElements WHERE MethodID = :id")
        linked_element_ids = [row[0] for row in conn.execute(linked_elements_q, {'id': method_id}).fetchall()]
    except Exception as e:
        flash(f"An error occurred while loading method elements: {e}", "danger")
        return redirect(url_for('manage_methods'))
    finally:
        if conn: conn.close()
        
    return render_template('manage_method_elements.html', method=method, all_elements=all_elements, linked_element_ids=linked_element_ids)

@app.route('/manage_qc_standards', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_qc_standards():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_qc_standards.html', standards=[])
    
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                standard_name = request.form.get('standard_name')
                description = request.form.get('description')
                
                exists = conn.execute(text("SELECT StandardID FROM QcStandards WHERE StandardName = :name"), {'name': standard_name}).fetchone()
                if exists:
                    flash(f"Error: A standard named '{standard_name}' already exists.", "danger")
                else:
                    conn.execute(text("INSERT INTO QcStandards (StandardName, Description) VALUES (:name, :desc)"), {'name': standard_name, 'desc': description})
                    flash(f"Standard '{standard_name}' added successfully.", "success")
            return redirect(url_for('manage_qc_standards'))

        standards = conn.execute(text("SELECT StandardID, StandardName, Description FROM QcStandards ORDER BY StandardName")).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        standards = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return render_template('manage_qc_standards.html', standards=standards)

@app.route('/manage_control_limits/<int:standard_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_control_limits(standard_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_qc_standards'))

    try:
        if request.method == 'POST':
            try:
                with conn.begin() as transaction:
                    params = {
                        'sid': standard_id,
                        'eid': request.form.get('element_id'),
                        'exp': request.form.get('expected_value'),
                        'warn': request.form.get('warning_limit'),
                        'ctrl': request.form.get('control_limit')
                    }
                    conn.execute(text("INSERT INTO ControlLimits (StandardID, ElementID, ExpectedValue, WarningLimit, ControlLimit) VALUES (:sid, :eid, :exp, :warn, :ctrl)"), params)
                flash("New control limit added successfully.", "success")
            except Exception as e: # Catches IntegrityError and others
                flash("Error: A limit for this element already exists for this standard.", "danger")
            
            return redirect(url_for('manage_control_limits', standard_id=standard_id))

        standard = conn.execute(text("SELECT StandardID, StandardName FROM QcStandards WHERE StandardID = :id"), {'id': standard_id}).fetchone()
        if not standard:
            flash("QC Standard not found.", "danger")
            return redirect(url_for('manage_qc_standards'))

        elements_q = text("SELECT ElementID, ElementName, ElementSymbol FROM Elements WHERE ElementID NOT IN (SELECT ElementID FROM ControlLimits WHERE StandardID = :sid) ORDER BY ElementName")
        elements = conn.execute(elements_q, {'sid': standard_id}).fetchall()
        
        limits_q = text("SELECT cl.LimitID, e.ElementName, e.ElementSymbol, cl.ExpectedValue, cl.WarningLimit, cl.ControlLimit FROM ControlLimits cl JOIN Elements e ON cl.ElementID = e.ElementID WHERE cl.StandardID = :sid ORDER BY e.ElementName")
        limits = conn.execute(limits_q, {'sid': standard_id}).fetchall()
        
        return render_template('manage_control_limits.html', standard=standard, elements=elements, limits=limits)
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('manage_qc_standards'))
    finally:
        if conn: conn.close()

@app.route('/delete_control_limit/<int:limit_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_control_limit(limit_id):
    standard_id = request.form.get('standard_id') # Needed for redirect
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_control_limits', standard_id=standard_id))
    try:
        with conn.begin() as transaction:
            conn.execute(text("DELETE FROM ControlLimits WHERE LimitID = :id"), {'id': limit_id})
        flash("Control limit deleted.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_control_limits', standard_id=standard_id))

@app.route('/advanced_reporting')
@login_required
@role_required('admin')
def advanced_reporting():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('advanced_reporting.html', results=[], clients=[], statuses=[])

    results, clients = [], []
    statuses = ['Received', 'In Prep', 'Awaiting Analysis', 'Analysis Complete', 'Reporting', 'QC Failed', 'Archived']
    client_id = request.args.get('client_id', '')
    status = request.args.get('status', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    params = {}

    try:
        sql_query = "SELECT b.BatchID, b.BatchCode, c.ClientName, b.DateReceived, b.Status, (SELECT COUNT(*) FROM Samples s WHERE s.BatchID = b.BatchID) as SampleCount FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID"
        where_clauses = []
        if client_id:
            where_clauses.append("b.ClientID = :cid")
            params['cid'] = client_id
        if status:
            where_clauses.append("b.Status = :status")
            params['status'] = status
        if start_date:
            where_clauses.append("b.DateReceived >= :start_date")
            params['start_date'] = start_date
        if end_date:
            where_clauses.append("b.DateReceived <= :end_date")
            params['end_date'] = end_date
        
        if where_clauses:
            sql_query += " WHERE " + " AND ".join(where_clauses)
        
        sql_query += " ORDER BY b.DateReceived DESC"
        
        results = conn.execute(text(sql_query), params).fetchall()

        if request.args.get('export') == 'true':
            df = pd.DataFrame(results) # Convert SQLAlchemy results to DataFrame
            df = df.drop(columns=['BatchID'])
            output = io.BytesIO()
            writer = pd.ExcelWriter(output, engine='xlsxwriter')
            df.to_excel(writer, index=False, sheet_name='Report')
            writer.close()
            output.seek(0)
            
            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename=AnarLab_Report_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
            response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            return response

        clients = conn.execute(text("SELECT ClientID, ClientName FROM Clients ORDER BY ClientName")).fetchall()
        
    except Exception as e:
        flash(f"An error occurred while generating the report: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    
    return render_template('advanced_reporting.html', results=results, clients=clients, statuses=statuses, selected_client=int(client_id) if client_id else None, selected_status=status, selected_start_date=start_date, selected_end_date=end_date)

@app.route('/manage_instruments', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_instruments():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_instruments.html', instruments=[])
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                params = {
                    'name': request.form.get('instrument_name'),
                    'code': request.form.get('instrument_code'),
                    'status': request.form.get('status')
                }
                conn.execute(text("INSERT INTO Instruments (InstrumentName, InstrumentCode, Status) VALUES (:name, :code, :status)"), params)
            flash('Instrument added successfully!', 'success')
            return redirect(url_for('manage_instruments'))
        
        instruments = conn.execute(text("SELECT InstrumentID, InstrumentName, InstrumentCode, Status FROM Instruments ORDER BY InstrumentName")).fetchall()
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        instruments = []
    finally:
        if conn: conn.close()
    return render_template('manage_instruments.html', instruments=instruments)

@app.route('/edit_instrument/<int:instrument_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_instrument(instrument_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_instruments'))
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                params = {
                    'name': request.form.get('instrument_name'),
                    'code': request.form.get('instrument_code'),
                    'status': request.form.get('status'),
                    'id': instrument_id
                }
                conn.execute(text("UPDATE Instruments SET InstrumentName = :name, InstrumentCode = :code, Status = :status WHERE InstrumentID = :id"), params)
            flash('Instrument updated successfully!', 'success')
            return redirect(url_for('manage_instruments'))

        instrument = conn.execute(text("SELECT * FROM Instruments WHERE InstrumentID = :id"), {'id': instrument_id}).fetchone()
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('manage_instruments'))
    finally:
        if conn: conn.close()
    return render_template('edit_instrument.html', instrument=instrument)

@app.route('/delete_instrument/<int:instrument_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_instrument(instrument_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_instruments'))
    try:
        with conn.begin() as transaction:
            res_count = conn.execute(text("SELECT COUNT(*) FROM Results WHERE InstrumentID = :id"), {'id': instrument_id}).scalar()
            qc_res_count = conn.execute(text("SELECT COUNT(*) FROM QcResults WHERE InstrumentID = :id"), {'id': instrument_id}).scalar()
            if res_count > 0 or qc_res_count > 0:
                flash("Cannot delete instrument with existing results. Mark it as 'Hors Service' instead.", "danger")
                return redirect(url_for('manage_instruments'))
            conn.execute(text("DELETE FROM Instruments WHERE InstrumentID = :id"), {'id': instrument_id})
        flash('Instrument deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting instrument: {e}', 'danger')
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_instruments'))

@app.route('/batch_details/<int:batch_id>')
@login_required
def batch_details(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(request.referrer or url_for('dashboard'))
    try:
        demande_q = text("""
            SELECT b.*, c.ClientName, c.ClientAddress, c.ContactPerson, c.ContactEmail, wd.* 
            FROM SampleBatches b 
            JOIN Clients c ON b.ClientID = c.ClientID 
            LEFT JOIN WorkOrderDetails wd ON b.BatchID = wd.BatchID 
            WHERE b.BatchID = :id
        """)
        demande = conn.execute(demande_q, {'id': batch_id}).fetchone()
        if not demande:
            flash("Batch not found.", "danger")
            return redirect(url_for('dashboard'))

        work_order_id = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).scalar_one()
        methods_q = text("""
            SELECT g.GroupName, m.MethodName FROM Methods m 
            JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID 
            JOIN ServiceGroups g ON m.GroupID = g.GroupID 
            WHERE wom.WorkOrderID = :woid ORDER BY g.GroupName, m.MethodName
        """)
        methods_by_group = conn.execute(methods_q, {'woid': work_order_id}).fetchall()
        
        samples = conn.execute(text("SELECT SampleID, ClientSampleID, SampleType, Weight, WeightFinal, Category FROM Samples WHERE BatchID = :id AND Category = 'Client Sample'"), {'id': batch_id}).fetchall()
        qc_results = conn.execute(text("SELECT s.ClientSampleID, s.Category, e.ElementSymbol, qr.ResultValue FROM QcResults qr JOIN Samples s ON qr.SampleID = s.SampleID JOIN Elements e ON qr.ElementID = e.ElementID WHERE s.BatchID = :id ORDER BY s.Category, s.ClientSampleID, e.ElementSymbol"), {'id': batch_id}).fetchall()
        
        # --- NEW LOGIC TO FETCH USED CONSUMABLES ---
        used_consumables_q = text("""
            SELECT ct.TypeName, cs.LotNumber
            FROM BatchConsumableUsage bcu
            JOIN ConsumableStock cs ON bcu.StockID = cs.StockID
            JOIN ConsumableTypes ct ON cs.ConsumableTypeID = ct.ConsumableTypeID
            WHERE bcu.BatchID = :id
            ORDER BY ct.TypeName
        """)
        used_consumables = conn.execute(used_consumables_q, {'id': batch_id}).fetchall()
        # --- END OF NEW LOGIC ---
        
        grouped_methods = {}
        for group_name, method_name in methods_by_group:
            if group_name not in grouped_methods: grouped_methods[group_name] = []
            grouped_methods[group_name].append(method_name)

        return render_template('batch_details.html', 
                               demande=demande, 
                               samples=samples, 
                               qc_results=qc_results, 
                               grouped_methods=grouped_methods,
                               used_consumables=used_consumables) # Pass the new data to the template
    except Exception as e:
        flash(f"An error occurred while fetching batch details: {e}", "danger")
        traceback.print_exc()
        return redirect(request.referrer or url_for('dashboard'))
    finally:
        if conn: conn.close()

@app.route('/edit_demande/<int:batch_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_demande(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_queue'))
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                params_batch = {
                    'code': request.form.get('batch_code'),
                    'date': request.form.get('reception_date'),
                    'id': batch_id
                }
                conn.execute(text("UPDATE SampleBatches SET BatchCode = :code, DateReceived = :date WHERE BatchID = :id"), params_batch)
                
                params_details = {
                    'st': request.form.get('sample_type'),
                    'pm': request.form.get('payment_mode'),
                    'rs': request.form.get('return_samples'),
                    'id': batch_id
                }
                conn.execute(text("UPDATE WorkOrderDetails SET SampleType = :st, PaymentMode = :pm, ReturnSamples = :rs WHERE BatchID = :id"), params_details)
                
                work_order_id = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).scalar_one()
                conn.execute(text("DELETE FROM WorkOrderMethods WHERE WorkOrderID = :woid"), {'woid': work_order_id})
                
                new_selected_method_ids = request.form.getlist('method_ids')
                if new_selected_method_ids:
                    method_data = [{'woid': work_order_id, 'mid': method_id} for method_id in new_selected_method_ids]
                    conn.execute(text("INSERT INTO WorkOrderMethods (WorkOrderID, MethodID) VALUES (:woid, :mid)"), method_data)
            
            log_action(batch_id, "Demande de prestation updated")
            flash("Demande updated successfully!", "success")
            return redirect(url_for('prep_queue'))

        # GET request
        demande = conn.execute(text("SELECT b.*, c.ClientName, wd.* FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID LEFT JOIN WorkOrderDetails wd ON b.BatchID = wd.BatchID WHERE b.BatchID = :id"), {'id': batch_id}).fetchone()
        service_groups = conn.execute(text("SELECT GroupID, GroupName FROM ServiceGroups ORDER BY GroupName")).fetchall()
        methods = conn.execute(text("SELECT MethodID, MethodName, GroupID FROM Methods ORDER BY MethodName")).fetchall()
        work_order_id = conn.execute(text("SELECT WorkOrderID FROM WorkOrders WHERE BatchID = :id"), {'id': batch_id}).scalar_one()
        selected_method_ids = [row[0] for row in conn.execute(text("SELECT MethodID FROM WorkOrderMethods WHERE WorkOrderID = :woid"), {'woid': work_order_id}).fetchall()]
        
        return render_template('edit_demande.html', demande=demande, service_groups=service_groups, methods=methods, selected_method_ids=selected_method_ids)
    except Exception as e:
        flash(f"Error loading/updating demande: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('prep_queue'))
    finally:
        if conn: conn.close()

@app.route('/audit_trail/<int:batch_id>')
@login_required
@role_required('admin')
def audit_trail(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(request.referrer or url_for('dashboard'))
    
    logs, batch_code = [], "Unknown"
    try:
        batch_code_row = conn.execute(text("SELECT BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
        if batch_code_row: batch_code = batch_code_row[0]
        
        query = text("SELECT l.Timestamp, u.Username, l.Action FROM AuditLog l LEFT JOIN Users u ON l.UserID = u.UserID WHERE l.BatchID = :id ORDER BY l.Timestamp ASC;")
        logs = conn.execute(query, {'id': batch_id}).fetchall()
    except Exception as e:
        flash(f"An error occurred while loading the audit trail: {e}", "danger")
        batch_code = "Error"
    finally:
        if conn: conn.close()
            
    return render_template('audit_trail.html', logs=logs, batch_code=batch_code, batch_id=batch_id)

@app.route('/reset_batch_results/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin')
def reset_batch_results(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('batch_details', batch_id=batch_id))
    
    try:
        with conn.begin() as transaction:
            status = conn.execute(text("SELECT Status FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).scalar_one_or_none()
            if not status or status != 'QC Failed':
                flash("Les résultats ne peuvent être réinitialisés que pour les lots en 'QC Failed'.", "warning")
                return redirect(url_for('batch_details', batch_id=batch_id))

            sample_ids = [row[0] for row in conn.execute(text("SELECT SampleID FROM Samples WHERE BatchID = :id"), {'id': batch_id}).fetchall()]
            
            if sample_ids:
                stmt_results = text("DELETE FROM Results WHERE SampleID IN :ids").bindparams(bindparam('ids', expanding=True))
                stmt_qc_results = text("DELETE FROM QcResults WHERE SampleID IN :ids").bindparams(bindparam('ids', expanding=True))
                conn.execute(stmt_results, {'ids': sample_ids})
                conn.execute(stmt_qc_results, {'ids': sample_ids})

            conn.execute(text("UPDATE SampleBatches SET Status = 'Awaiting Analysis', Location = 'Chemical Analysis Unit', CertificateStatus = NULL WHERE BatchID = :id"), {'id': batch_id})
        
        # APPEL CORRIGÉ ICI
        log_action(conn, batch_id, "Analytical results reset after QC failure.")
        
        flash("Les résultats analytiques ont été supprimés. Vous pouvez maintenant réimporter le fichier corrigé.", "success")
        return redirect(url_for('enter_results', batch_id=batch_id))

    except Exception as e:
        flash(f"Une erreur est survenue lors de la réinitialisation : {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('batch_details', batch_id=batch_id))
    finally:
        if conn:
            conn.close()

@app.route('/reporting_queue')
@login_required
@role_required('admin', 'analyst')
def reporting_queue():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('reporting_queue.html', batches=[], total_pages=1, current_page=1, search_term='', start_date='', end_date='')
    
    # --- Initialize variables with safe defaults BEFORE the try block ---
    batches = []
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    total_pages = 1
    
    try:
        params = {}
        # Use a list to build WHERE clauses for easier management
        where_clauses = ["b.Location = 'Reporting'", "b.Status <> 'Archived'"]

        if search_term:
            where_clauses.append("(b.BatchCode LIKE :search OR c.ClientName LIKE :search)")
            params['search'] = f'%{search_term}%'
        if start_date:
            where_clauses.append("b.DateReceived >= :start_date")
            params['start_date'] = start_date
        if end_date:
            # Add time component to end_date to include the full day
            where_clauses.append("b.DateReceived <= :end_date_full")
            params['end_date_full'] = f"{end_date} 23:59:59"
            
        # Join the WHERE clauses together
        full_where_clause = " AND ".join(where_clauses)
        
        # Optimized query for counting total batches
        count_query = text(f"SELECT COUNT(b.BatchID) FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE {full_where_clause}")
        total_batches = conn.execute(count_query, params).scalar()
        
        PER_PAGE = int(get_setting('ItemsPerPage', 20))
        total_pages = math.ceil(total_batches / PER_PAGE) if total_batches > 0 else 1
        offset = (page - 1) * PER_PAGE
        
        # Optimized data query with explicit pagination
        data_query = text(f"""
            SELECT b.BatchID, b.BatchCode, c.ClientName, b.Status, b.CertificateStatus 
            FROM SampleBatches b 
            JOIN Clients c ON b.ClientID = c.ClientID 
            WHERE {full_where_clause}
            ORDER BY b.DateReceived DESC 
            OFFSET :offset ROWS FETCH NEXT :per_page ROWS ONLY
        """)
        params['offset'] = offset
        params['per_page'] = PER_PAGE
        
        batches = conn.execute(data_query, params).fetchall()

    except Exception as e:
        flash(f"An error occurred while fetching the reporting queue: {e}", "danger")
        traceback.print_exc()
        # On error, the function will continue, and the default empty 'batches' list will be used.
    
    finally:
        if conn:
            conn.close()
        
    # --- This return statement is now OUTSIDE the try block and will ALWAYS be executed ---
    return render_template('reporting_queue.html', 
                           batches=batches, 
                           search_term=search_term, 
                           start_date=start_date, 
                           end_date=end_date, 
                           current_page=page, 
                           total_pages=total_pages)

# In app.py, find and REPLACE the archive_batch function with this one.

@app.route('/archive_batch/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin')
def archive_batch(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Erreur de connexion a la BDD.", "danger")
        return redirect(url_for('reporting_queue'))

    try:
        with conn.begin() as transaction:
            # CORRECTION : Utiliser 'conn' pour exécuter la requête
            can_archive = conn.execute(text(
                "SELECT BatchID FROM SampleBatches WHERE BatchID = :id AND CertificateStatus = 'Approved'"
            ), {'id': batch_id}).first()
            
            if not can_archive:
                flash("Impossible d'archiver. Le certificat doit d'abord être approuvé.", "warning")
                return redirect(url_for('reporting_queue'))

            # L'appel à _update_batch_flow est correct et utilise 'conn'
            _update_batch_flow(
                conn,
                batch_id=batch_id,
                to_status="Archived",
                to_location="Reporting", # La localisation physique ne change généralement pas
                event_name="Batch Archived",
                user_id=current_user.id
            )
        
        flash("Le lot a été archivé avec succès.", "success")
    except Exception as e:
        flash(f"Une erreur est survenue lors de l'archivage: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return redirect(url_for('reporting_queue'))

@app.route('/manage_blank_limits', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_blank_limits():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))
    try:
        if request.method == 'POST':
            try:
                with conn.begin() as transaction:
                    params = {
                        'eid': request.form.get('element_id'),
                        'limit': request.form.get('control_limit')
                    }
                    conn.execute(text("INSERT INTO BlankControlLimits (ElementID, ControlLimit) VALUES (:eid, :limit)"), params)
                flash("New blank control limit added successfully.", "success")
            except Exception: # Catches IntegrityError for duplicates
                flash("Error: A limit for this element already exists.", "danger")
            return redirect(url_for('manage_blank_limits'))

        elements_q = text("SELECT ElementID, ElementName, ElementSymbol FROM Elements WHERE ElementID NOT IN (SELECT ElementID FROM BlankControlLimits) ORDER BY ElementName")
        elements = conn.execute(elements_q).fetchall()
        
        limits_q = text("SELECT bcl.LimitID, e.ElementName, e.ElementSymbol, bcl.ControlLimit FROM BlankControlLimits bcl JOIN Elements e ON bcl.ElementID = e.ElementID ORDER BY e.ElementName")
        limits = conn.execute(limits_q).fetchall()
        
        return render_template('manage_blank_limits.html', elements=elements, limits=limits)
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        if conn: conn.close()

@app.route('/delete_blank_limit/<int:limit_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_blank_limit(limit_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_blank_limits'))
    try:
        with conn.begin() as transaction:
            conn.execute(text("DELETE FROM BlankControlLimits WHERE LimitID = :id"), {'id': limit_id})
        flash("Blank control limit deleted.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_blank_limits'))

@app.route('/control_charts')
@login_required
@role_required('admin', 'analyst')
def control_charts():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('dashboard'))
    
    selected_standard_id = request.args.get('standard_id', type=int)
    selected_element_id = request.args.get('element_id', type=int)
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    chart_data_json = "{}"

    try:
        if selected_standard_id and selected_element_id:
            params_limits = {'sid': selected_standard_id, 'eid': selected_element_id}
            limits = conn.execute(text("SELECT * FROM ControlLimits WHERE StandardID = :sid AND ElementID = :eid"), params_limits).fetchone()
            
            if limits:
                params_results = {'sid': selected_standard_id, 'eid': selected_element_id}
                sql_query = "SELECT qr.ResultValue, qr.AnalysisDate FROM QcResults qr JOIN Samples s ON qr.SampleID = s.SampleID WHERE s.StandardID = :sid AND qr.ElementID = :eid"
                if start_date:
                    sql_query += " AND qr.AnalysisDate >= :start_date"
                    params_results['start_date'] = start_date
                if end_date:
                    sql_query += " AND qr.AnalysisDate < :end_date"
                    params_results['end_date'] = (datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
                sql_query += " ORDER BY qr.AnalysisDate"
                
                results = conn.execute(text(sql_query), params_results).fetchall()
                
                chart_data = {
                    'labels': [r.AnalysisDate.strftime('%Y-%m-%d %H:%M') for r in results if r.AnalysisDate],
                    'values': [r.ResultValue for r in results],
                    'expected': limits.ExpectedValue,
                    'upper_control': limits.ExpectedValue + limits.ControlLimit,
                    'lower_control': limits.ExpectedValue - limits.ControlLimit,
                    'upper_warning': limits.ExpectedValue + limits.WarningLimit,
                    'lower_warning': limits.ExpectedValue - limits.WarningLimit,
                }
                chart_data_json = json.dumps(chart_data, cls=CustomJSONEncoder)

        standards = conn.execute(text("SELECT StandardID, StandardName FROM QcStandards ORDER BY StandardName")).fetchall()
        elements = conn.execute(text("SELECT ElementID, ElementName, ElementSymbol FROM Elements ORDER BY ElementName")).fetchall()
    
    except Exception as e:
        flash(f"An error occurred on the control charts page: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    
    return render_template('control_charts.html', 
                           standards=standards, 
                           elements=elements, 
                           selected_standard_id=selected_standard_id, 
                           selected_element_id=selected_element_id, 
                           start_date=start_date, 
                           end_date=end_date, 
                           chart_data_json=chart_data_json)

@app.route('/manage_prep_tasks', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_prep_tasks():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_prep_tasks.html', tasks=[])
    try:
        if request.method == 'POST':
            task_name = request.form.get('task_name')
            if task_name:
                with conn.begin() as transaction:
                    conn.execute(text("INSERT INTO PrepTasks (TaskName) VALUES (:name)"), {'name': task_name})
                flash("Preparation task added successfully!", "success")
            return redirect(url_for('manage_prep_tasks'))
        
        tasks = conn.execute(text("SELECT TaskID, TaskName, IsActive FROM PrepTasks ORDER BY TaskName")).fetchall()
    except Exception as e:
        flash(f"Error: {e}", "danger")
        tasks = []
    finally:
        if conn: conn.close()
    return render_template('manage_prep_tasks.html', tasks=tasks)

@app.route('/delete_prep_task/<int:task_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_prep_task(task_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_prep_tasks'))
    try:
        with conn.begin() as transaction:
            conn.execute(text("DELETE FROM PrepTasks WHERE TaskID = :id"), {'id': task_id})
        flash("Task deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting task: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_prep_tasks'))

@app.route('/manage_prep_equipment', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_prep_equipment():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_prep_equipment.html', equipment=[])
    try:
        if request.method == 'POST':
            equipment_name = request.form.get('equipment_name')
            if equipment_name:
                with conn.begin() as transaction:
                    conn.execute(text("INSERT INTO PrepEquipment (EquipmentName) VALUES (:name)"), {'name': equipment_name})
                flash("Equipment added successfully!", "success")
            return redirect(url_for('manage_prep_equipment'))
        
        equipment = conn.execute(text("SELECT EquipmentID, EquipmentName, Status FROM PrepEquipment ORDER BY EquipmentName")).fetchall()
    except Exception as e:
        flash(f"Error: {e}", "danger")
        equipment = []
    finally:
        if conn: conn.close()
    return render_template('manage_prep_equipment.html', equipment=equipment)

@app.route('/delete_prep_equipment/<int:equipment_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_prep_equipment(equipment_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_prep_equipment'))
    try:
        with conn.begin() as transaction:
            conn.execute(text("DELETE FROM PrepEquipment WHERE EquipmentID = :id"), {'id': equipment_id})
        flash("Equipment deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting equipment: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_prep_equipment'))

@app.route('/export_results_excel/<int:batch_id>')
@login_required
@role_required('admin', 'analyst')
def export_results_excel(batch_id):
    conn = get_db_connection() # Obtenir la connexion
    if not conn:
        flash("Database engine is not available.", "danger")
        return redirect(url_for('reporting_queue'))
    try:
        sql_query = text("SELECT s.ClientSampleID, e.ElementSymbol, r.ResultValue FROM Results r JOIN Samples s ON r.SampleID = s.SampleID JOIN Elements e ON r.ElementID = e.ElementID WHERE s.BatchID = :id AND s.Category = 'Client Sample'")
        # Note: il est préférable d'utiliser la connexion (conn) plutôt que le moteur (engine) pour pandas ici
        results_df = pd.read_sql(sql_query, conn, params={'id': batch_id})
        
        if results_df.empty:
            flash("No client sample results found to export for this batch.", "warning")
            return redirect(url_for('reporting_queue'))

        pivoted_df = results_df.pivot_table(index='ClientSampleID', columns='ElementSymbol', values='ResultValue').reset_index()
        pivoted_df.rename_axis(None, axis=1, inplace=True)
        
        batch_code = conn.execute(text("SELECT BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).scalar_one()

        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')
        pivoted_df.to_excel(writer, index=False, sheet_name=f'Results_{batch_code}')
        worksheet = writer.sheets[f'Results_{batch_code}']
        for i, col in enumerate(pivoted_df.columns):
            worksheet.set_column(i, i, max(len(str(col)), pivoted_df[col].astype(str).map(len).max()) + 2)
        writer.close()
        output.seek(0)
        
        # --- C'EST LA LIGNE QUI A ÉTÉ CORRIGÉE ---
        log_action(conn, batch_id, "Generated Excel export of final results.")

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=Results_{batch_code}.xlsx"
        response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response
    except Exception as e:
        flash(f"An error occurred while generating the Excel export: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('reporting_queue'))
    finally:
        if conn:
            conn.close() # S'assurer que la connexion est fermée

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_users.html', users=[])
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                username, password, role = request.form.get('username'), request.form.get('password'), request.form.get('role')
                if not all([username, password, role]):
                    flash("Username, password, and role are all required.", "warning")
                    return redirect(url_for('manage_users'))
                
                exists = conn.execute(text("SELECT UserID FROM Users WHERE Username = :name"), {'name': username}).fetchone()
                if exists:
                    flash(f"Error: Username '{username}' already exists.", "danger")
                    return redirect(url_for('manage_users'))

                password_hash = generate_password_hash(password)
                conn.execute(text("INSERT INTO Users (Username, PasswordHash, Role) VALUES (:name, :hash, :role)"), {'name': username, 'hash': password_hash, 'role': role})
            flash(f"User '{username}' created successfully.", "success")
            return redirect(url_for('manage_users'))

        users = conn.execute(text("SELECT UserID, Username, Role FROM Users WHERE UserID != :id ORDER BY Username"), {'id': current_user.id}).fetchall()
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        users = []
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_users'))
    try:
        if request.method == 'POST':
            with conn.begin() as transaction:
                params = {
                    'role': request.form.get('role'),
                    'name': request.form.get('username'),
                    'id': user_id
                }
                conn.execute(text("UPDATE Users SET Role = :role, Username = :name WHERE UserID = :id"), params)
            flash("User details updated successfully.", "success")
            return redirect(url_for('manage_users'))

        user = conn.execute(text("SELECT UserID, Username, Role FROM Users WHERE UserID = :id"), {'id': user_id}).fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('manage_users'))
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('manage_users'))
    finally:
        if conn: conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_users'))
    try:
        with conn.begin() as transaction:
            if user_id == current_user.id:
                flash("You cannot delete your own account.", "danger")
                return redirect(url_for('manage_users'))
            
            log_count = conn.execute(text("SELECT COUNT(*) FROM AuditLog WHERE UserID = :id"), {'id': user_id}).scalar()
            if log_count > 0:
                flash("Cannot delete user with existing audit log entries.", "danger")
                return redirect(url_for('manage_users'))

            conn.execute(text("DELETE FROM Users WHERE UserID = :id"), {'id': user_id})
        flash("User deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting user: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_users'))

@app.route('/reset_user_password/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def reset_user_password(user_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('manage_users'))
    try:
        new_password = request.form.get('new_password')
        if not new_password or len(new_password) < 4:
            flash("New password must be at least 4 characters long.", "warning")
            return redirect(url_for('edit_user', user_id=user_id))
        
        with conn.begin() as transaction:
            new_password_hash = generate_password_hash(new_password)
            conn.execute(text("UPDATE Users SET PasswordHash = :hash WHERE UserID = :id"), {'hash': new_password_hash, 'id': user_id})
        flash("User password has been reset successfully.", "success")
    except Exception as e:
        flash(f"An error occurred while resetting the password: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_users'))

@app.route('/export_prep_worksheet/<int:batch_id>')
@login_required
@role_required('admin', 'technician')
def export_prep_worksheet(batch_id):
    """
    Exports an Excel worksheet for a batch, ready for final weight entry.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_batch', batch_id=batch_id))

    try:
        # We now use the connection pool 'engine' for pandas
        sql_query = text("SELECT ClientSampleID, WeightFinal FROM Samples WHERE BatchID = :id ORDER BY SampleID")
        df = pd.read_sql(sql_query, engine, params={'id': batch_id})
        
        batch_code = conn.execute(text("SELECT BatchCode FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).scalar_one()

        output = io.BytesIO()
        # Use with statement for writer to ensure it's closed properly
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Prep_Worksheet')
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={batch_code}_prep_worksheet.xlsx"
        response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response
    except Exception as e:
        flash(f"An error occurred during export: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('prep_batch', batch_id=batch_id))
    finally:
        if conn: conn.close()


@app.route('/import_prep_weights/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def import_prep_weights(batch_id):
    """
    Imports an Excel file with final weights and updates the database.
    """
    uploaded_file = request.files.get('weights_file')
    if not uploaded_file or uploaded_file.filename == '':
        flash("No file selected for import.", "warning")
        return redirect(url_for('prep_batch', batch_id=batch_id))

    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_batch', batch_id=batch_id))
    
    try:
        df = pd.read_excel(uploaded_file, dtype={'ClientSampleID': str})
        if 'ClientSampleID' not in df.columns or 'WeightFinal' not in df.columns:
            raise ValueError("Excel file must contain 'ClientSampleID' and 'WeightFinal' columns.")

        with conn.begin() as transaction:
            # Get existing samples from the DB to match against the Excel file
            samples_in_db_q = text("SELECT SampleID, ClientSampleID FROM Samples WHERE BatchID = :id")
            samples_in_db = {row.ClientSampleID.strip(): row.SampleID for row in conn.execute(samples_in_db_q, {'id': batch_id}).fetchall()}
            
            updates_to_perform = []
            for index, row in df.iterrows():
                client_id = str(row['ClientSampleID']).strip()
                sample_id = samples_in_db.get(client_id)
                
                if sample_id and pd.notna(row['WeightFinal']):
                    updates_to_perform.append({'weight': float(row['WeightFinal']), 'id': sample_id})
            
            if updates_to_perform:
                conn.execute(text("UPDATE Samples SET WeightFinal = :weight WHERE SampleID = :id"), updates_to_perform)
                log_action(conn, batch_id, f"Imported final weights for {len(updates_to_perform)} samples via Excel.")
                flash(f"Successfully imported and updated {len(updates_to_perform)} final weights.", "success")
            else:
                flash("No matching samples found or no weights provided in the file to update.", "warning")

    except Exception as e:
        flash(f"An error occurred during import: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return redirect(url_for('prep_batch', batch_id=batch_id))

@app.route('/manage_consumables', methods=['GET'])
@login_required
@role_required('admin', 'technician')
def manage_consumables():
    """
    Main page for managing the inventory. Now includes search and filtering.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return render_template('manage_consumables.html', stock=[], types=[], suppliers=[], search_filters={}, now=datetime.now())

    # --- Initialize search filters and variables ---
    search_term = request.args.get('search', '').strip()
    supplier_id = request.args.get('supplier_id', '')
    search_filters = {'search': search_term, 'supplier_id': supplier_id}
    
    consumable_stock = []
    
    try:
        # --- Build a dynamic query ---
        params = {}
        base_query = """
            FROM ConsumableStock cs
            JOIN ConsumableTypes ct ON cs.ConsumableTypeID = ct.ConsumableTypeID
            LEFT JOIN Suppliers s ON cs.SupplierID = s.SupplierID
            WHERE cs.Quantity > 0
        """
        
        if search_term:
            base_query += " AND (ct.TypeName LIKE :search OR cs.LotNumber LIKE :search)"
            params['search'] = f'%{search_term}%'
        
        if supplier_id:
            base_query += " AND cs.SupplierID = :sid"
            params['sid'] = int(supplier_id)

        stock_query = text(f"""
            SELECT cs.StockID, ct.TypeName, s.SupplierName, cs.LotNumber, cs.DateReceived, 
                   cs.ExpiryDate, cs.Quantity, cs.Unit
            {base_query}
            ORDER BY ct.TypeName, cs.ExpiryDate
        """)
        consumable_stock = conn.execute(stock_query, params).fetchall()
        
        consumable_types = conn.execute(text("SELECT * FROM ConsumableTypes ORDER BY TypeName")).fetchall()
        suppliers = conn.execute(text("SELECT * FROM Suppliers ORDER BY SupplierName")).fetchall()

    except Exception as e:
        flash(f"An error occurred while loading the inventory page: {e}", "danger")
        traceback.print_exc()
        consumable_types, suppliers = [], []
    
    finally:
        if conn:
            conn.close()

    # --- THE FIX IS HERE: We pass the current time to the template ---
    return render_template('manage_consumables.html', 
                           stock=consumable_stock,
                           types=consumable_types,
                           suppliers=suppliers,
                           search_filters=search_filters,
                           now=datetime.now()) # Pass the current time as 'now'

@app.route('/record_consumable_usage/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def record_consumable_usage(batch_id):
    """
    Handles the form submission from the prep_batch page to link consumables to a batch.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_batch', batch_id=batch_id))

    try:
        with conn.begin() as transaction:
            selected_stock_ids = request.form.getlist('stock_ids')

            # First, clear any existing usage records for this batch to allow updates
            conn.execute(text("DELETE FROM BatchConsumableUsage WHERE BatchID = :bid"), {'bid': batch_id})

            if selected_stock_ids:
                # Prepare data for a bulk insert
                usage_data = [{'bid': batch_id, 'sid': stock_id, 'uid': current_user.id} for stock_id in selected_stock_ids]
                conn.execute(text("""
                    INSERT INTO BatchConsumableUsage (BatchID, StockID, UserID)
                    VALUES (:bid, :sid, :uid)
                """), usage_data)

            log_action(conn=conn, batch_id=batch_id, action_description=f"Recorded/Updated usage of {len(selected_stock_ids)} consumable item(s).")
            flash("Consumable usage has been recorded successfully for this batch.", "success")

    except Exception as e:
        flash(f"An error occurred while recording consumable usage: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('prep_batch', batch_id=batch_id))


@app.route('/complete_prep/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def complete_prep(batch_id):
    """
    Updates final weights for all samples in a batch and moves the batch
    to the next location (Chemical Analysis Unit).
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_queue'))

    try:
        with conn.begin() as transaction:
            updates_to_perform = []
            for key, final_weight in request.form.items():
                if key.startswith('weight_final_'):
                    sample_id = int(key.split('_')[-1])
                    if final_weight:
                        updates_to_perform.append({'weight': float(final_weight), 'id': sample_id})

            if updates_to_perform:
                conn.execute(text("UPDATE Samples SET WeightFinal = :weight WHERE SampleID = :id"), updates_to_perform)

            new_status = "Awaiting Analysis"
            new_location = "Chemical Analysis Unit"
            conn.execute(text("UPDATE SampleBatches SET Status = :status, Location = :loc WHERE BatchID = :id"),
                         {'status': new_status, 'loc': new_location, 'id': batch_id})

            batch_code = conn.execute(text('SELECT BatchCode FROM SampleBatches WHERE BatchID = :id'), {'id': batch_id}).scalar_one()

        log_action(conn, batch_id, f"Final weights recorded for {len(updates_to_perform)} samples. Preparation stage completed.")
        flash(f"Preparation for batch {batch_code} has been completed and moved to {new_location}.", "success")

    except Exception as e:
        flash(f"An error occurred while completing preparation: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('prep_batch', batch_id=batch_id))
    finally:
        if conn:
            conn.close()

    return redirect(url_for('prep_queue'))

@app.route('/inventory/delete_supplier/<int:supplier_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_supplier(supplier_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            # Check if this supplier is in use before deleting
            usage_count = conn.execute(text("SELECT COUNT(*) FROM ConsumableStock WHERE SupplierID = :id"), {'id': supplier_id}).scalar()
            if usage_count > 0:
                flash("Cannot delete supplier. It is linked to one or more stock items.", "danger")
            else:
                conn.execute(text("DELETE FROM Suppliers WHERE SupplierID = :id"), {'id': supplier_id})
                flash("Supplier deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))

@app.route('/inventory/delete_type/<int:type_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_consumable_type(type_id):
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            # Check if this type is in use
            usage_count = conn.execute(text("SELECT COUNT(*) FROM ConsumableStock WHERE ConsumableTypeID = :id"), {'id': type_id}).scalar()
            if usage_count > 0:
                flash("Cannot delete type. It is linked to one or more stock items.", "danger")
            else:
                conn.execute(text("DELETE FROM ConsumableTypes WHERE ConsumableTypeID = :id"), {'id': type_id})
                flash("Consumable type deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))

@app.route('/inventory/deplete_stock/<int:stock_id>', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def deplete_stock_item(stock_id):
    """
    Sets the quantity of a stock item to 0. A safe alternative to hard deletion.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            conn.execute(text("UPDATE ConsumableStock SET Quantity = 0 WHERE StockID = :id"), {'id': stock_id})
        flash("Stock item marked as depleted (Quantity set to 0).", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))

@app.route('/review_batch/<int:batch_id>')
@login_required
@role_required('admin') # Only admins can review and approve
def review_batch(batch_id):
    """
    Displays a final review page for an admin to see all results and QC
    before approving or rejecting the certificate.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('reporting_queue'))
    
    try:
        # Fetch batch and client details
        batch_q = text("SELECT b.*, c.ClientName FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE b.BatchID = :id")
        batch = conn.execute(batch_q, {'id': batch_id}).fetchone()

        # Fetch client sample results into a pivot table for easy display
        results_sql = text("""
            SELECT s.ClientSampleID, e.ElementSymbol, r.ResultValue 
            FROM Results r 
            JOIN Samples s ON r.SampleID = s.SampleID 
            JOIN Elements e ON r.ElementID = e.ElementID 
            WHERE s.BatchID = :id AND s.Category = 'Client Sample'
        """)
        results_df = pd.read_sql(results_sql, conn, params={'id': batch_id})
        pivoted_results = results_df.pivot_table(index='ClientSampleID', columns='ElementSymbol', values='ResultValue').fillna('-')
        elements_in_order = sorted(pivoted_results.columns.tolist())

        # Fetch all QC results for final review
        qc_results_q = text("""
            SELECT s.ClientSampleID, s.Category, e.ElementSymbol, qr.ResultValue 
            FROM QcResults qr 
            JOIN Samples s ON qr.SampleID = s.SampleID 
            JOIN Elements e ON qr.ElementID = e.ElementID 
            WHERE s.BatchID = :id 
            ORDER BY s.Category, s.ClientSampleID, e.ElementSymbol
        """)
        qc_results = conn.execute(qc_results_q, {'id': batch_id}).fetchall()

        return render_template('review_batch.html', 
                               batch=batch,
                               pivoted_results=pivoted_results,
                               elements_in_order=elements_in_order,
                               qc_results=qc_results)
    except Exception as e:
        flash(f"An error occurred while loading the review page: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('reporting_queue'))
    finally:
        if conn: conn.close()

@app.route('/process_approval/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin')
def process_approval(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Erreur de connexion a la BDD.", "danger")
        return redirect(url_for('reporting_queue'))
        
    try:
        action = request.form.get('action') # 'Approve' ou 'Reject'
        user_id = current_user.id

        with conn.begin() as transaction:  # La transaction est gérée ici
            # --- TOUTES LES REQUÊTES UTILISENT 'conn' ---
            current = conn.execute(text("SELECT Status, Location FROM SampleBatches WHERE BatchID = :id"), {'id': batch_id}).fetchone()
            if not current:
                flash("Lot non trouve.", "danger")
                return redirect(url_for('reporting_queue'))

            if action == 'Approve':
                new_cert_status = 'Approved'
                event_name = "Certificate Approved"
                conn.execute(text("UPDATE SampleBatches SET CertificateVersion = CertificateVersion + 1 WHERE BatchID = :id"), {'id': batch_id})
            else:
                new_cert_status = 'Rejected'
                event_name = "Certificate Rejected"

            update_q = text("""
                UPDATE SampleBatches 
                SET CertificateStatus = :status, 
                    CertificateApprovedByUserID = :uid, 
                    CertificateApprovalDate = GETUTCDATE()
                WHERE BatchID = :id
            """)
            conn.execute(update_q, {'status': new_cert_status, 'uid': user_id, 'id': batch_id})

            flow_event_q = text("""
                INSERT INTO FlowEvents (BatchID, EventName, StatusFrom, LocationFrom, StatusTo, LocationTo, CreatedByUserID, Metadata)
                VALUES (:bid, :event, :s_from, :l_from, :s_to, :l_to, :uid, :meta);
            """)
            conn.execute(flow_event_q, {
                'bid': batch_id, 'event': event_name, 's_from': current.Status, 'l_from': current.Location,
                's_to': current.Status, 'l_to': current.Location, 'uid': user_id,
                'meta': json.dumps({"certificate_status": new_cert_status})
            })

            log_action(conn, batch_id, f"Certificat marqué comme '{new_cert_status}' par l'utilisateur.")

        flash(f"Le lot a bien été '{new_cert_status}'.", "success")
        
    except Exception as e:
        flash(f"Une erreur est survenue durant le processus d'approbation: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return redirect(url_for('reporting_queue'))

@app.route('/inventory/add_stock', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def add_stock():
    """
    Handles the form submission for adding a new stock item to the inventory.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            expiry_date = request.form.get('expiry_date')
            params = {
                'type_id': request.form.get('consumable_type_id'),
                'supplier_id': request.form.get('supplier_id') or None,
                'lot': request.form.get('lot_number'),
                'received': request.form.get('date_received'),
                'expiry': expiry_date if expiry_date else None,
                'qty': request.form.get('quantity'),
                'unit': request.form.get('unit')
            }
            conn.execute(text("""
                INSERT INTO ConsumableStock (ConsumableTypeID, SupplierID, LotNumber, DateReceived, ExpiryDate, Quantity, Unit)
                VALUES (:type_id, :supplier_id, :lot, :received, :expiry, :qty, :unit)
            """), params)
        flash("New stock item added successfully.", "success")
    except Exception as e:
        flash(f"Error adding stock: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))


@app.route('/inventory/add_supplier', methods=['POST'])
@login_required
@role_required('admin')
def add_supplier():
    """
    Handles the form submission for adding a new supplier.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            params = { 'name': request.form.get('supplier_name'), 'contact': request.form.get('contact_info') or None }
            conn.execute(text("INSERT INTO Suppliers (SupplierName, ContactInfo) VALUES (:name, :contact)"), params)
        flash("Supplier added successfully.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))


@app.route('/inventory/add_consumable_type', methods=['POST'])
@login_required
@role_required('admin')
def add_consumable_type():
    """
    Handles the form submission for adding a new type of consumable.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Error.", "danger")
        return redirect(url_for('manage_consumables'))
    try:
        with conn.begin() as transaction:
            params = { 'name': request.form.get('type_name'), 'desc': request.form.get('description') or None }
            conn.execute(text("INSERT INTO ConsumableTypes (TypeName, Description) VALUES (:name, :desc)"), params)
        flash("Consumable type added successfully.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    finally:
        if conn: conn.close()
    return redirect(url_for('manage_consumables'))

# --- ADD THIS NEW FUNCTION TO app.py ---

@app.route('/unarchive_batch/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin')
def unarchive_batch(batch_id):
    conn = get_db_connection()
    if not conn:
        flash("Erreur de connexion a la BDD.", "danger")
        return redirect(url_for('advanced_reporting'))
    
    try:
        with conn.begin() as transaction:
            # Changer le statut du lot
            update_q = text("""
                UPDATE SampleBatches 
                SET Status = 'Analysis Complete'
                WHERE BatchID = :id AND Status = 'Archived'
            """)
            result = conn.execute(update_q, {'id': batch_id})
            
            if result.rowcount > 0:
                # CORRECTION : Utiliser 'conn' pour l'appel à log_action
                log_action(conn, batch_id, "Batch has been un-archived.")
                flash("Le lot a ete restaure avec succes.", "success")
            else:
                flash("Le lot n'a pas pu etre restaure (il n'etait peut-etre pas archive).", "warning")
        
    except Exception as e:
        flash(f"Une erreur de base de donnees est survenue lors de la restauration: {e}", "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close()
        
    return redirect(url_for('advanced_reporting'))

@app.route('/export_prep_report/<int:batch_id>')
@login_required
@role_required('admin', 'technician')
def export_prep_report(batch_id):
    """
    Generates a formal PDF report summarizing the preparation stage,
    including final weights and equipment/tasks used.
    """
    conn = get_db_connection()
    if not conn:
        flash("Database Connection Error.", "danger")
        return redirect(url_for('prep_batch', batch_id=batch_id))

    try:
        # Fetch main batch and client info
        batch_q = text("SELECT b.*, c.ClientName FROM SampleBatches b JOIN Clients c ON b.ClientID = c.ClientID WHERE b.BatchID = :id")
        batch = conn.execute(batch_q, {'id': batch_id}).fetchone()

        # Fetch sample details with weights
        samples_q = text("SELECT ClientSampleID, Weight, WeightFinal FROM Samples WHERE BatchID = :id ORDER BY SampleID")
        samples = conn.execute(samples_q, {'id': batch_id}).fetchall()

        # Fetch the logged prep tasks and equipment for this batch
        prep_log_q = text("""
            SELECT pt.TaskName, pe.EquipmentName, u.Username
            FROM BatchPrepLog bpl
            LEFT JOIN PrepTasks pt ON bpl.TaskID = pt.TaskID
            LEFT JOIN PrepEquipment pe ON bpl.EquipmentID = pe.EquipmentID
            JOIN Users u ON bpl.UserID = u.UserID
            WHERE bpl.BatchID = :id
        """)
        prep_logs = conn.execute(prep_log_q, {'id': batch_id}).fetchall()

        # Organize the logs for easy display
        prep_info = {
            "tasks": [log.TaskName for log in prep_logs if log.TaskName],
            "equipment": [log.EquipmentName for log in prep_logs if log.EquipmentName],
            "user": prep_logs[0].Username if prep_logs else "N/A",
            "date": prep_logs[0].CompletionDate.strftime('%Y-%m-%d %H:%M') if prep_logs and hasattr(prep_logs[0], 'CompletionDate') else datetime.now().strftime('%Y-%m-%d')
        }
        
        # Generate the PDF
        html_out = render_template('prep_report_template.html', 
                                   batch=batch, 
                                   samples=samples,
                                   prep_info=prep_info)
        return generate_pdf_response(html_out, f'PrepReport_{batch.BatchCode}')

    except Exception as e:
        flash(f"An error occurred while generating the prep report: {e}", "danger")
        traceback.print_exc()
        return redirect(url_for('prep_batch', batch_id=batch_id))
    finally:
        if conn:
            conn.close()   

def _update_batch_flow(conn, batch_id, to_status, to_location, event_name, user_id, metadata={}):
    """
    Helper transactionnel pour mettre à jour l'état d'un lot et enregistrer tous les événements.
    """
    current_state_q = text("SELECT Status, Location FROM SampleBatches WHERE BatchID = :id")
    current = conn.execute(current_state_q, {'id': batch_id}).fetchone()
    
    if not current:
        raise ValueError(f"Tentative de mise à jour d'un lot inexistant (ID: {batch_id})")

    update_q = text("UPDATE SampleBatches SET Status = :to_status, Location = :to_location, StageStartedAt = GETUTCDATE() WHERE BatchID = :id;")
    conn.execute(update_q, {'to_status': to_status, 'to_location': to_location, 'id': batch_id})
    
    flow_event_q = text("INSERT INTO FlowEvents (BatchID, EventName, StatusFrom, LocationFrom, StatusTo, LocationTo, CreatedByUserID, Metadata) VALUES (:bid, :event, :s_from, :l_from, :s_to, :l_to, :uid, :meta);")
    conn.execute(flow_event_q, {
        'bid': batch_id, 'event': event_name, 's_from': current.Status, 'l_from': current.Location,
        's_to': to_status, 'l_to': to_location, 'uid': user_id,
        'meta': json.dumps(metadata) if metadata else None
    })
    
    # MODIFICATION : Passe l'objet 'conn' à log_action
    log_text = f"Événement de workflow '{event_name}': Statut -> '{to_status}' @ '{to_location}'."
    log_action(conn, batch_id, log_text)    

@app.route('/api/flow/dispatch/<int:batch_id>', methods=['POST'])
@login_required
@role_required('admin', 'technician')
def api_dispatch_batch(batch_id):
    user_id = request.json.get('user_id')
    if not user_id: return jsonify({"status": "error", "message": "user_id est requis"}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"status": "error", "message": "Erreur de connexion BDD"}), 500
    
    try:
        with conn.begin() as transaction:
            # La transaction commence ici pour toutes les opérations
            wo_id_q = text("SELECT WorkOrderID FROM WorkOrders wo JOIN SampleBatches sb ON wo.BatchID = sb.BatchID WHERE sb.BatchID = :id AND sb.Location = 'Reception'")
            wo_id = conn.execute(wo_id_q, {'id': batch_id}).scalar_one_or_none()

            if not wo_id:
                return jsonify({"status": "error", "message": f"Lot #{batch_id} non trouvé ou pas en Réception."}), 404

            req_prep_q = text("SELECT 1 FROM Methods m JOIN WorkOrderMethods wom ON m.MethodID = wom.MethodID WHERE wom.WorkOrderID = :wo_id AND m.RequiresPrep = 1")
            requires_prep = conn.execute(req_prep_q, {'wo_id': wo_id}).first()

            if requires_prep:
                to_location, to_status, event_name = "Mechanical Prep Unit", "Received", "Dispatch To Prep"
            else:
                to_location, to_status, event_name = "Chemical Analysis Unit", "Awaiting Analysis", "Dispatch To Analysis"

            _update_batch_flow(conn, batch_id, to_status, to_location, event_name, user_id)
        
        # La transaction est validée ici
        return jsonify({"status": "success", "message": f"Lot envoyé vers {to_location}"})
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if conn: conn.close()

# Endpoint pour les KPIs du tableau de bord
@app.route('/api/stats/kpi')
@login_required
def api_get_kpi():
    # Ici, nous mettrions la logique SQL complete pour calculer les KPIs.
    # Voici une version simplifiee utilisant les donnees existantes.
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    try:
        kpi = {}
        # Les comptes sont bases sur vos definitions
        kpi['received'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'Received' AND Location = 'Reception'")).scalar()
        kpi['in_prep'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Location = 'Mechanical Prep Unit'")).scalar()
        kpi['awaiting_analysis'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'Awaiting Analysis'")).scalar()
        kpi['qc_failed'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Status = 'QC Failed'")).scalar()
        kpi['reporting'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE Location = 'Reporting' AND (CertificateStatus IS NULL OR CertificateStatus = 'Rejected')")).scalar()
        kpi['approved'] = conn.execute(text("SELECT COUNT(*) FROM SampleBatches WHERE CertificateStatus = 'Approved' AND Status <> 'Archived'")).scalar()

        # Placeholders pour les metriques complexes - necessitent des requetes avancees sur FlowEvents
        kpi['tat_p50'] = 0.0 # TODO: A calculer a partir de FlowEvents
        kpi['tat_p90'] = 0.0 # TODO: A calculer
        kpi['qc_oos_rate'] = 0.0 # TODO: A calculer a partir de QcAlerts
        kpi['sla_ok_rate'] = 0.0 # TODO: A calculer a partir de SlaDueAt

        return jsonify(kpi)
    finally:
        if conn: conn.close()

# Endpoint pour les alertes QC
@app.route('/api/qc/alerts')
@login_required
def api_get_qc_alerts():
    window = request.args.get('window', '14d')
    days = int(window.replace('d', ''))
    start_date = datetime.utcnow() - timedelta(days=days)

    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    try:
        q = text("""
            SELECT q.AlertID, b.BatchCode, e.ElementSymbol, q.RuleViolated, q.MeasuredValue, q.ExpectedValue, q.Severity, q.AlertDate
            FROM QcAlerts q
            JOIN SampleBatches b ON q.BatchID = b.BatchID
            JOIN Elements e ON q.ElementID = e.ElementID
            WHERE q.AlertDate >= :start_date ORDER BY q.AlertDate DESC
        """)
        alerts_raw = conn.execute(q, {'start_date': start_date}).mappings().fetchall()
        # Rendre serialisable en JSON
        alerts = [dict(row) for row in alerts_raw]
        return jsonify(alerts)
    finally:
        if conn: conn.close()

class EnhancedDORValidator:
    def __init__(self, conn):
        self.conn = conn
        self.rules = self._load_rules()

    def _load_rules(self):
        rules_q = text("SELECT RuleName, RuleType, CheckLogic, Parameters_JSON, ErrorMessage FROM ValidationRules WHERE IsActive = 1")
        return self.conn.execute(rules_q).fetchall()

    def validate(self, dataframe):
        errors = []
        for rule in self.rules:
            validation_method = getattr(self, rule.CheckLogic, None)
            if validation_method:
                try:
                    params = json.loads(rule.Parameters_JSON) if rule.Parameters_JSON else {}
                    rule_errors = validation_method(dataframe, **params)
                    if rule_errors:
                        errors.append({'rule': rule.RuleName, 'message': rule.ErrorMessage, 'details': rule_errors})
                except Exception as e:
                    errors.append({'rule': rule.RuleName, 'message': f"Erreur système dans la règle: {e}", 'details': []})
        return errors

    def _check_required_columns(self, df, columns=[]):
        missing_cols = [col for col in columns if col not in df.columns]
        return missing_cols if missing_cols else None

    def _check_numeric_weight(self, df, **kwargs):
        if 'Weight' in df.columns:
            non_numeric = df[pd.to_numeric(df['Weight'], errors='coerce').isnull() & df['Weight'].notnull()]
            if not non_numeric.empty:
                return non_numeric['ClientSampleID'].tolist()
        return None
        
    def _check_valid_category(self, df, **kwargs):
        valid_categories = {'Client Sample', 'Blank', 'Standard', 'Duplicate'}
        if 'Category' in df.columns:
            invalid_rows = df[~df['Category'].isin(valid_categories)]
            if not invalid_rows.empty:
                return invalid_rows['ClientSampleID'].tolist()
        return None

    # --- Implémentation des fonctions de validation ---
    
    def _check_required_columns(self, df, columns=[]):
        """Vérifie si toutes les colonnes requises sont présentes."""
        missing_cols = [col for col in columns if col not in df.columns]
        return missing_cols if missing_cols else None

    def _check_numeric_weight(self, df, **kwargs):
        """Vérifie si la colonne 'Weight' est numérique."""
        if 'Weight' in df.columns:
            non_numeric = df[pd.to_numeric(df['Weight'], errors='coerce').isnull() & df['Weight'].notnull()]
            if not non_numeric.empty:
                return non_numeric['ClientSampleID'].tolist()
        return None
        
    def _check_valid_category(self, df, **kwargs):
        """Vérifie que les catégories sont valides."""
        valid_categories = {'Client Sample', 'Blank', 'Standard', 'Duplicate'}
        if 'Category' in df.columns:
            invalid_rows = df[~df['Category'].isin(valid_categories)]
            if not invalid_rows.empty:
                return invalid_rows['ClientSampleID'].tolist()
        return None

@app.route('/api/v2/reception/validate-dor', methods=['POST'])
@login_required
def api_validate_dor_v2():
    if 'sample_file' not in request.files:
        return jsonify({'success': False, 'errors': [{'message': 'Aucun fichier fourni.'}]}), 400

    file = request.files['sample_file']
    if file.filename == '':
        return jsonify({'success': False, 'errors': [{'message': 'Aucun fichier sélectionné.'}]}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'errors': [{'message': 'Erreur de connexion à la BDD.'}]}), 500
    
    try:
        df = pd.read_excel(io.BytesIO(file.read()), dtype={'ClientSampleID': str})
        df.rename(columns=lambda x: x.strip(), inplace=True)
        
        validator = EnhancedDORValidator(conn)
        errors = validator.validate(df)
        
        if errors:
            return jsonify({'success': False, 'errors': errors})
        else:
            return jsonify({'success': True, 'message': 'Fichier valide ! Les règles de base sont respectées.'})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'errors': [{'message': f"Erreur de traitement du fichier: {e}"}]}), 500
    finally:
        if conn: conn.close()

class AdvancedDuplicateDetector:
    def __init__(self, conn):
        self.conn = conn

    def find_exact_matches(self, sample_ids):
        """
        Recherche les correspondances exactes et UNIQUES pour une liste de ClientSampleID.
        """
        if not sample_ids:
            return []
        
        # AJOUT DE DISTINCT pour ne retourner chaque ID qu'une seule fois
        query = text("SELECT DISTINCT ClientSampleID FROM Samples WHERE ClientSampleID IN :ids")
        query = query.bindparams(bindparam('ids', expanding=True))
        
        results = self.conn.execute(query, {'ids': list(set(sample_ids))}).fetchall()
        
        return [row.ClientSampleID for row in results]

@app.route('/api/v2/reception/check-duplicates', methods=['POST'])
@login_required
def api_check_duplicates_v2():
    if 'sample_file' not in request.files:
        return jsonify({'success': False, 'message': 'Aucun fichier fourni.'}), 400

    file = request.files['sample_file']
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Erreur de connexion BDD.'}), 500
    
    try:
        df = pd.read_excel(io.BytesIO(file.read()), dtype={'ClientSampleID': str})
        
        # S'assurer que la colonne requise existe
        if 'ClientSampleID' not in df.columns:
            return jsonify({'success': False, 'message': "Le fichier Excel ne contient pas la colonne 'ClientSampleID'."})

        # Extraire les IDs non vides de la colonne
        sample_ids_to_check = df['ClientSampleID'].dropna().unique().tolist()
        
        detector = AdvancedDuplicateDetector(conn)
        found_duplicates = detector.find_exact_matches(sample_ids_to_check)
        
        if found_duplicates:
            return jsonify({
                'success': False, 
                'message': 'Des doublons potentiels ont été trouvés.',
                'duplicates': found_duplicates
            })
        else:
            return jsonify({'success': True, 'message': 'Aucun doublon trouvé.'})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'message': f"Erreur de traitement du fichier: {e}"}), 500
    finally:
        if conn: conn.close()

# --- Main Execution ---
if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)