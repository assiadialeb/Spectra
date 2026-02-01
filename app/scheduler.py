from flask_apscheduler import APScheduler
from datetime import datetime
from app.models import db, Project, Scan, Secret
from app.scanners.scan_engine import ScanEngine
from app.scanners.nuclei_engine import NucleiEngine
import threading
import atexit

scheduler = APScheduler()

def init_scheduler(app):
    """
    Initialize the scheduler and register the master polling job.
    """
    if scheduler.running:
        return

    # Config for APScheduler
    app.config['SCHEDULER_API_ENABLED'] = True # Optional, exposes API
    
    scheduler.init_app(app)
    scheduler.start()
    
    # Ensure scheduler shuts down when app exits
    atexit.register(lambda: scheduler.shutdown(wait=False))
    
    # Register the master job to run every minute
    scheduler.add_job(
        id='master_scan_poller',
        func=check_and_run_scheduled_scans,
        trigger='interval',
        minutes=1,
        args=[app],
        replace_existing=True,
        misfire_grace_time=60
    )
    print(f"Scheduler started: Polling for scheduled scans every minute. (Server Time: {datetime.now().strftime('%H:%M:%S')})")

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
        print(f"[Scheduler Heartbeat] Checking {len(projects)} active projects at {current_time_str}...")
        
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
    Launches a unified scheduled scan based on project configuration.
    """
    # 1. Load Configuration
    config = project.scan_configuration if project.scan_configuration else {}
    
    # Determine Scope
    run_sast = config.get('run_sast', True)
    run_dast = config.get('run_dast', False)
    
    # Determine Unified Scan Type
    if run_sast and run_dast:
        unified_scan_type = 'FULL'
    elif run_dast:
        unified_scan_type = 'DAST'
    else:
        unified_scan_type = 'SAST' # Default
    
    print(f"[Scheduler] Triggering Unified Scan for Project {project.id}. Type: {unified_scan_type}")

    # Update last run timestamp immediately
    project.last_scheduled_scan = datetime.now()
    db.session.commit()
    
    # Create ONE Scan record
    inc_secrets = config.get('enable_gitleaks', True) if run_sast else False
    
    scan = Scan(
        project_id=project.id, 
        status='RUNNING', 
        scan_type=unified_scan_type,
        include_secrets=inc_secrets,
        configuration=config
    )
    db.session.add(scan)
    db.session.commit()
    
    # Start Worker
    t = threading.Thread(target=_run_unified_worker, args=(app, scan.id, run_sast, run_dast))
    t.start()

def run_scan_now(app, scan_id):
    """
    Manually triggers a scan execution.
    For manual scans, we need to infer run_sast/run_dast from the scan_type stored in DB,
    or just run what the scan says.
    """
    scheduler.add_job(
        id=f'manual_scan_{scan_id}',
        func=_run_manual_worker_wrapper,
        trigger='date',
        run_date=datetime.now(),
        args=[app, scan_id]
    )
    print(f"Manual scan {scan_id} scheduled for immediate execution.")

def _run_manual_worker_wrapper(app, scan_id):
    """
    Infers scope from scan_type and calls the unified worker.
    """
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        
        run_sast = False
        run_dast = False
        
        if scan.scan_type == 'SAST':
            run_sast = True
        elif scan.scan_type == 'DAST':
            run_dast = True
        elif scan.scan_type == 'FULL':
            run_sast = True
            run_dast = True
        else:
            # Fallback for manual legacy scans
            run_sast = True 
            
        _run_unified_worker(app, scan_id, run_sast, run_dast)

def _run_unified_worker(app, scan_id, run_sast, run_dast):
    """
    Unified Worker that runs SAST and DAST sequentially and aggregates results.
    """
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        print(f"[Worker] Starting Scan {scan.id} (Type: {scan.scan_type})...")
        scan_config = scan.configuration if scan.configuration else {}
        
        # Aggregated Results Containers
        all_vulnerabilities = []
        all_quality_issues = []
        all_secrets = []
        
        try:
            # --- PHASE 1: SAST (Code Analysis) ---
            if run_sast:
                print(f"[Worker] Running SAST phase for Scan {scan.id}...")
                engine = ScanEngine(scan.id)
                # SAST Run
                s_vulns, s_quality, s_secrets = engine.run(
                    scan.project.repositories, 
                    include_secrets=scan.include_secrets, 
                    config=scan_config
                )
                all_vulnerabilities.extend(s_vulns)
                all_quality_issues.extend(s_quality)
                all_secrets.extend(s_secrets)
                print(f"[Worker] SAST Finished. Found {len(s_vulns)} vulns, {len(s_secrets)} secrets.")

            # --- PHASE 2: DAST (Web Analysis) ---
            if run_dast:
                print(f"[Worker] Running DAST phase for Scan {scan.id}...")
                if scan.project.target_urls:
                    nuclei_engine = NucleiEngine(scan.id)
                    d_vulns = nuclei_engine.run(scan.project.target_urls, config=scan_config)
                    all_vulnerabilities.extend(d_vulns)
                    print(f"[Worker] DAST Finished. Found {len(d_vulns)} vulns.")
                else:
                    print(f"[Worker] DAST skipped: No target URLs.")

            # --- PHASE 3: Saving & Grading ---
            print(f"[Worker] Saving total results for Scan {scan.id}...")
            
            # Save Results to DB
            for vuln in all_vulnerabilities:
                vuln.scan_id = scan.id # Ensure ID linkage
                db.session.add(vuln)
            
            for issue in all_quality_issues:
                issue.scan_id = scan.id
                db.session.add(issue)
                
            for secret_data in all_secrets:
                # Secret might use dict unpacking, ensure scan_id is present
                if 'scan_id' in secret_data:
                    del secret_data['scan_id']
                secret = Secret(scan_id=scan.id, **secret_data)
                db.session.add(secret)

            # --- Grading ---
            # Security Score
            critical_count = sum(1 for v in all_vulnerabilities if v.severity == 'CRITICAL')
            high_count = sum(1 for v in all_vulnerabilities if v.severity == 'HIGH') + len(all_secrets)
            medium_count = sum(1 for v in all_vulnerabilities if v.severity == 'MEDIUM')
            
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
                
            # Quality Score (Weighted mostly by SAST finding)
            quality_penalty = 0
            for q in all_quality_issues:
                if q.severity == 'HIGH': quality_penalty += 5
                elif q.severity == 'MEDIUM': quality_penalty += 2
                else: quality_penalty += 0.5
            
            # If DAST only, quality is perfect (100). If combined, SAST penalty applies.
            if not run_sast and run_dast:
                q_score = 100
            else:
                q_score = max(0, 100 - int(quality_penalty))
            
            scan.quality_score = q_score
            if q_score >= 90: scan.quality_grade = 'A'
            elif q_score >= 80: scan.quality_grade = 'B'
            elif q_score >= 60: scan.quality_grade = 'C'
            elif q_score >= 40: scan.quality_grade = 'D'
            else: scan.quality_grade = 'F'

            scan.status = 'COMPLETED'
            db.session.commit()
            print(f"[Worker] Unified Scan {scan.id} completed successfully.")
            
        except Exception as e:
            print(f"[Worker] Unified Scan {scan.id} FAILED: {e}")
            import traceback
            traceback.print_exc()
            scan.status = 'FAILED'
            db.session.commit()
