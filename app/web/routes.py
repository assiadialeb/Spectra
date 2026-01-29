from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import db, Project, Repository, Scan, Vulnerability
from app.models_settings import Settings
from app.scanners.scan_engine import ScanEngine
from datetime import datetime
import subprocess # Placeholder for scanner integration
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
    return render_template('project_detail.html', project=project)

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

@web.route('/projects/<int:project_id>/scan', methods=['POST'])
def run_scan(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Create Scan Record
    scan = Scan(project_id=project.id, status='RUNNING')
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
    
    try:
        # Initialize Engine
        engine = ScanEngine(scan.id)
        
        # Run Scan
        vulnerabilities = engine.run(scan.project.repositories)
        
        # Save Results
        for vuln in vulnerabilities:
            db.session.add(vuln)
            
        scan.status = 'COMPLETED'
        db.session.commit()
        return "OK"
        
    except Exception as e:
        print(f"Scan Execution Failed: {e}")
        scan.status = 'FAILED'
        db.session.commit()
        return "FAILED", 500

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
    
    return render_template('scan_report.html', scan=scan, results=sorted_results)

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

@web.route('/repositories/<int:repo_id>/delete', methods=['POST'])
def delete_repository(repo_id):
    repo = Repository.query.get_or_404(repo_id)
    project_id = repo.project_id
    db.session.delete(repo)
    db.session.commit()
    flash('Repository removed.')
    return redirect(url_for('web.project_detail', project_id=project_id))

@web.route('/projects/<int:project_id>/repositories/add', methods=['POST'])
def add_repository(project_id):
    project = Project.query.get_or_404(project_id)
    url = request.form.get('url')
    if url:
        # Basic name extraction from URL
        repo_name = url.strip().rstrip('/').split('/')[-1]
        repo = Repository(project_id=project.id, url=url.strip(), name=repo_name)
        db.session.add(repo)
        db.session.commit()
        flash('Repository added.')
    return redirect(url_for('web.project_detail', project_id=project_id))

@web.route('/history')
def history():
    # Limit to last 50 scans for performance
    scans = Scan.query.order_by(Scan.timestamp.desc()).limit(50).all()
    return render_template('history.html', scans=scans)
