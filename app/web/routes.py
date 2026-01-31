from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import db, Project, Repository, Scan, Vulnerability, Secret
from app.models_settings import Settings
from app.scanners.scan_engine import ScanEngine
from datetime import datetime
from app.scanners.scan_engine import ScanEngine
from datetime import datetime
import threading
import sys
# In real implem, we would import ScanEngine

web = Blueprint('web', __name__)

@web.route('/')
def index():
    return redirect(url_for('web.dashboard'))

@web.route('/dashboard')
def dashboard():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('dashboard.html', projects=projects)

@web.route('/projects/new', methods=['GET', 'POST'])
def create_project():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        repos_text = request.form.get('repositories') # Simple text area for now, line separated URLs
        
        if not name:
            flash('Project name is required.')
            return redirect(url_for('web.create_project'))
            
        project = Project(name=name, description=description)
        db.session.add(project)
        db.session.commit()
        
        # Add repositories
        if repos_text:
            repo_urls = [line.strip() for line in repos_text.split('\n') if line.strip()]
            for url in repo_urls:
                # Basic name extraction from URL
                repo_name = url.rstrip('/').split('/')[-1]
                repo = Repository(project_id=project.id, url=url, name=repo_name)
                db.session.add(repo)
            db.session.commit()
            
        return redirect(url_for('web.project_detail', project_id=project.id))
        
    return render_template('create_project.html')

@web.route('/projects/<int:project_id>')
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Prepare Data for Dashboard Charts
    # We need chronological order for charts (Oldest -> Newest)
    scans = sorted(project.scans, key=lambda s: s.timestamp)
    
    dates = []
    vuln_critical = []
    vuln_high = []
    vuln_medium = []
    secrets_count = []
    quality_high = []
    quality_medium = []
    
    for scan in scans:
        if scan.status != 'COMPLETED':
            continue
            
        dates.append(scan.timestamp.strftime('%Y-%m-%d %H:%M'))
        
        # Vulns
        vuln_critical.append(sum(1 for v in scan.results if v.severity == 'CRITICAL'))
        vuln_high.append(sum(1 for v in scan.results if v.severity == 'HIGH'))
        vuln_medium.append(sum(1 for v in scan.results if v.severity == 'MEDIUM'))
        
        # Secrets
        secrets_count.append(len(scan.secrets))
        
        # Quality
        quality_high.append(sum(1 for q in scan.quality_issues if q.severity == 'HIGH' or q.severity == 'ERROR'))
        quality_medium.append(sum(1 for q in scan.quality_issues if q.severity == 'MEDIUM' or q.severity == 'WARNING'))

    chart_data = {
        'dates': dates,
        'vulns': {
            'critical': vuln_critical,
            'high': vuln_high,
            'medium': vuln_medium
        },
        'secrets': secrets_count,
        'quality': {
            'high': quality_high,
            'medium': quality_medium
        }
    }
    
    # Pagination for Scan History Table
    page = request.args.get('page', 1, type=int)
    scan_pagination = Scan.query.filter_by(project_id=project_id).order_by(Scan.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
    
    return render_template('project_detail.html', project=project, chart_data=chart_data, scan_pagination=scan_pagination)

@web.route('/projects/<int:project_id>/settings')
def project_settings(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project_settings.html', project=project)

@web.route('/projects/<int:project_id>/delete', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    try:
        db.session.delete(project)
        db.session.commit()
        flash('Project and all related data deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting project.', 'error')
        print(f"Delete Error: {e}")
        
    return redirect(url_for('web.dashboard'))

@web.route('/projects/<int:project_id>/update', methods=['POST'])
def update_project_description(project_id):
    project = Project.query.get_or_404(project_id)
    description = request.form.get('description')
    
    if description is not None:
        project.description = description
        db.session.commit()
        
    return redirect(url_for('web.project_settings', project_id=project.id))

@web.route('/projects/<int:project_id>/schedule', methods=['POST'])
def update_project_schedule(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Checkbox logic: if present = 'on' (True), if missing = None (False)
    schedule_enabled = request.form.get('schedule_enabled') == 'on'
    
    project.schedule_enabled = schedule_enabled
    if schedule_enabled:
        project.schedule_frequency = request.form.get('frequency', 'daily')
        project.schedule_time = request.form.get('time', '00:00') 
        project.schedule_day = request.form.get('day')
    
    db.session.commit()
    flash('Scan schedule updated.')
    
    return redirect(url_for('web.project_settings', project_id=project.id))

@web.route('/projects/<int:project_id>/repositories/add', methods=['POST'])
def add_repository(project_id):
    project = Project.query.get_or_404(project_id)
    repo_url = request.form.get('repo_url')
    
    if repo_url:
        repo_name = repo_url.rstrip('/').split('/')[-1]
        repo = Repository(project_id=project.id, url=repo_url, name=repo_name)
        db.session.add(repo)
        db.session.commit()
        flash('Repository added successfully.')
    else:
        flash('Repository URL cannot be empty.', 'error')
        
    return redirect(url_for('web.project_settings', project_id=project.id))

@web.route('/projects/<int:project_id>/repositories/<int:repo_id>/delete', methods=['POST'])
def delete_repository(project_id, repo_id):
    project = Project.query.get_or_404(project_id)
    repository = Repository.query.get_or_404(repo_id)
    
    if repository.project_id != project.id:
        flash('Repository does not belong to this project.', 'error')
        return redirect(url_for('web.project_settings', project_id=project.id))
        
    try:
        db.session.delete(repository)
        db.session.commit()
        flash('Repository deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting repository.', 'error')
        print(f"Delete Repository Error: {e}")
        
    return redirect(url_for('web.project_settings', project_id=project.id))

@web.route('/projects/<int:project_id>/scan', methods=['POST'])
def run_scan(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Get options from form
    include_secrets = request.form.get('include_secrets') == 'on'
    
    # Create Scan Record
    scan = Scan(project_id=project.id, status='RUNNING', include_secrets=include_secrets)
    db.session.add(scan)
    db.session.commit()
    
    # Render a progress/loading page that will trigger the actual scan logic (or do it synchronously here for V1 as requested)
    # "Le scan est réalisé en tâche de fond en v2, mais pour la v1 il attends et voit une indication d'avancement"
    
    # For V1 synchronous "Simulation" or actual execution, we can do it here.
    # But browsers timeout. If the user wants to see "Scan en cours...", we should probably stream response or use JS polling.
    # However, "synchronous" might just mean "server blocks until done".
    # Let's try to implement a simple "loading" view that does the scan then redirects.
    
    return render_template('scan_progress.html', project=project, scan=scan)

@web.route('/scans/<int:scan_id>/execute')
def execute_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Delegate execution to the scheduler module which handles context better
    from app.scheduler import run_scan_now
    from flask import current_app
    app_real = current_app._get_current_object()
    
    run_scan_now(app_real, scan_id)
    
    return "STARTED"



@web.route('/api/scans/<int:scan_id>/status')
def check_scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return {
        "status": scan.status,
        "id": scan.id
    }

@web.route('/scans/<int:scan_id>')
def scan_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Custom sort for severity
    severity_order = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3,
        'INFO': 4,
        'UNKNOWN': 5
    }
    
    sorted_results = sorted(
        scan.results, 
        key=lambda v: severity_order.get(v.severity, 6)
    )
    
    # Sort secrets by Date (Newest first)
    sorted_secrets = sorted(
        scan.secrets,
        key=lambda s: s.commit_date if s.commit_date else datetime.min,
        reverse=True
    )
    
    return render_template('scan_report.html', scan=scan, results=sorted_results, secrets=sorted_secrets)

@web.route('/scans/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    project_id = scan.project_id
    
    try:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting scan.', 'error')
        print(f"Delete Scan Error: {e}")
        
    return redirect(url_for('web.project_detail', project_id=project_id))

@web.route('/scans/<int:scan_id>/report/download')
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if AI settings are present, if not, maybe warn? But generator handles None provider gracefully.
    
    from app.reports.report_generator import ReportGenerator
    from flask import send_file
    
    generator = ReportGenerator()
    report_file = generator.generate_report(scan)
    
    filename = f"Spectra_Audit_{scan.project.name}_{scan.timestamp.strftime('%Y%m%d')}.docx"
    
    return send_file(
        report_file,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )

@web.route('/settings', methods=['GET', 'POST'])
def settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
        db.session.commit()
        
    if request.method == 'POST':
        settings.company_name = request.form.get('company_name')
        settings.language = request.form.get('language')
        settings.github_pat = request.form.get('github_pat')
        settings.ai_provider = request.form.get('ai_provider')
        settings.ai_api_key = request.form.get('ai_api_key')
        settings.ai_model = request.form.get('ai_model')
        settings.ai_api_url = request.form.get('ai_api_url')
        
        db.session.commit()
        flash('Settings updated successfully.')
        return redirect(url_for('web.settings'))
        
    return render_template('settings.html', settings=settings)



@web.route('/history')
def history():
    page = request.args.get('page', 1, type=int)
    # Paginate results, 20 per page
    pagination = Scan.query.order_by(Scan.timestamp.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('history.html', pagination=pagination)
