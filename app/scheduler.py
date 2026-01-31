from flask_apscheduler import APScheduler
from datetime import datetime
from app.models import db, Project, Scan
from app.scanners.scan_engine import ScanEngine
import threading

scheduler = APScheduler()

def init_scheduler(app):
    """
    Initialize the scheduler and register the master polling job.
    """
    # Config for APScheduler
    app.config['SCHEDULER_API_ENABLED'] = True # Optional, exposes API
    
    scheduler.init_app(app)
    scheduler.start()
    
    # Register the master job to run every minute
    scheduler.add_job(
        id='master_scan_poller',
        func=check_and_run_scheduled_scans,
        trigger='interval',
        minutes=1,
        args=[app]
    )
    print("Scheduler started: Polling for scheduled scans every minute.")

def check_and_run_scheduled_scans(app):
    """
    Checks all projects for due scheduled scans.
    """
    with app.app_context():
        now = datetime.now()
        current_time_str = now.strftime('%H:%M')
        current_day_str = now.strftime('%A').lower() # monday, tuesday...
        
        # Get enabled projects
        projects = Project.query.filter_by(schedule_enabled=True).all()
        
        for project in projects:
            try:
                should_run = False
                
                # Check Time Match
                if project.schedule_time != current_time_str:
                    continue
                
                # Check Frequency
                if project.schedule_frequency == 'daily':
                    # Check if already ran today
                    if project.last_scheduled_scan:
                        if project.last_scheduled_scan.date() == now.date():
                            continue # Already ran today
                    should_run = True
                    
                elif project.schedule_frequency == 'weekly':
                    # Check Day
                    if project.schedule_day and project.schedule_day.lower() != current_day_str:
                        continue
                    
                    # Check if already ran today (which is the scheduled day)
                    if project.last_scheduled_scan:
                        if project.last_scheduled_scan.date() == now.date():
                            continue
                    should_run = True
                
                if should_run:
                    print(f"Triggering Scheduled Scan for Project: {project.name} ({project.id})")
                    trigger_scheduled_scan(app, project)
                    
            except Exception as e:
                print(f"Error checking schedule for project {project.id}: {e}")

def trigger_scheduled_scan(app, project):
    """
    Launches the scan and updates the last_scheduled_scan timestamp.
    """
    # 1. Create Scan Record
    # By default scheduled scans include secrets? Let's assume Yes or use default from Project config (if we had one)
    # For now, default True
    scan = Scan(project_id=project.id, status='RUNNING', include_secrets=True)
    db.session.add(scan)
    
    # Update last run
    project.last_scheduled_scan = datetime.now()
    
    db.session.commit()
    
    # 2. Run Scan (Async thread)
    # We create a new thread to not block the scheduler loop
    # We need to pass 'app._get_current_object()' if using proxies, or just 'app' since passed from init
    thread = threading.Thread(target=_run_scan_worker, args=(app, scan.id))
    thread.start()

def _run_scan_worker(app, scan_id):
    """
    Worker similar to routes._perform_scan but for scheduler.
    Ideally we should refactor routes._perform_scan to be a shared function in a service.
    For now, I'll allow a bit of duplication or import it from routes? 
    Circular import risk if I import routes here.
    Better to duplicate the logic wrapper or move logic to a service.
    
    Given I cannot easily refactor routes.py purely without risk, I will re-implement the execution wrapper here.
    It basically calls ScanEngine.run().
    """
    from app.scanners.scan_engine import ScanEngine
    from app.models import Secret
    
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        try:
            engine = ScanEngine(scan.id)
            vulnerabilities, quality_issues, secrets = engine.run(scan.project.repositories, include_secrets=scan.include_secrets)
            
            # Save Results
            for vuln in vulnerabilities:
                db.session.add(vuln)
            
            for issue in quality_issues:
                db.session.add(issue)
                
            for secret_data in secrets:
                secret = Secret(scan_id=scan.id, **secret_data)
                db.session.add(secret)

            # --- Grading (Duplicated from routes.py, ideally shared) ---
            # Security Score
            critical_count = sum(1 for v in vulnerabilities if v.severity == 'CRITICAL')
            high_count = sum(1 for v in vulnerabilities if v.severity == 'HIGH') + len(secrets)
            medium_count = sum(1 for v in vulnerabilities if v.severity == 'MEDIUM')
            
            if critical_count > 0:
                scan.security_grade = 'F'; scan.security_score = 40
            elif high_count > 0:
                scan.security_grade = 'D'; scan.security_score = 55
            elif medium_count > 5:
                scan.security_grade = 'C'; scan.security_score = 70
            elif medium_count > 0:
                scan.security_grade = 'B'; scan.security_score = 85
            else:
                scan.security_grade = 'A'; scan.security_score = 100
                
            # Quality Score
            quality_penalty = 0
            for q in quality_issues:
                if q.severity == 'HIGH': quality_penalty += 5
                elif q.severity == 'MEDIUM': quality_penalty += 2
                else: quality_penalty += 0.5
            q_score = max(0, 100 - int(quality_penalty))
            scan.quality_score = q_score
            
            if q_score >= 90: scan.quality_grade = 'A'
            elif q_score >= 80: scan.quality_grade = 'B'
            elif q_score >= 60: scan.quality_grade = 'C'
            elif q_score >= 40: scan.quality_grade = 'D'
            else: scan.quality_grade = 'F'

            scan.status = 'COMPLETED'
            db.session.commit()
            print(f"[Scheduler] Scan {scan.id} completed.")
            
        except Exception as e:
            print(f"[Scheduler] Scan {scan.id} failed: {e}")
            scan.status = 'FAILED'
            db.session.commit()
