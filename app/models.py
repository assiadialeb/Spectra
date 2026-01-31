from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Automatic Scheduling
    schedule_enabled = db.Column(db.Boolean, default=False)
    schedule_frequency = db.Column(db.String(20), default='daily') # 'daily', 'weekly'
    schedule_time = db.Column(db.String(5), default='00:00') # 'HH:MM'
    schedule_day = db.Column(db.String(10), nullable=True) # 'monday', etc. (for weekly)
    last_scheduled_scan = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    repositories = db.relationship('Repository', backref='project', lazy=True, cascade="all, delete-orphan")
    target_urls = db.relationship('TargetURL', backref='project', lazy=True, cascade="all, delete-orphan")
    scans = db.relationship('Scan', backref='project', lazy=True, cascade="all, delete-orphan")

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False) 

class TargetURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='PENDING') # PENDING, RUNNING, COMPLETED, FAILED
    
    # Metrics / Grades (V2)
    security_grade = db.Column(db.String(2), nullable=True) # A, B, C...
    quality_grade = db.Column(db.String(2), nullable=True) # A, B, C...
    security_score = db.Column(db.Integer, nullable=True) # 0-100
    quality_score = db.Column(db.Integer, nullable=True) # 0-100
    
    # Configuration
    scan_type = db.Column(db.String(10), default='SAST') # SAST, DAST
    include_secrets = db.Column(db.Boolean, default=True)
    
    # Relationships
    results = db.relationship('Vulnerability', backref='scan', lazy=True, cascade="all, delete-orphan")
    quality_issues = db.relationship('QualityIssue', backref='scan', lazy=True, cascade="all, delete-orphan")
    secrets = db.relationship('Secret', backref='scan', lazy=True, cascade="all, delete-orphan")

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    # Core Data
    title = db.Column(db.String(255)) # Description of what rule matched
    match = db.Column(db.Text) # The actual secret (masked usually)
    rule_id = db.Column(db.String(100))
    
    # Location
    file_path = db.Column(db.String(255))
    start_line = db.Column(db.Integer, nullable=True)
    end_line = db.Column(db.Integer, nullable=True)
    
    # Git History Context
    commit_sha = db.Column(db.String(40))
    commit_message = db.Column(db.Text)
    commit_date = db.Column(db.DateTime)
    author = db.Column(db.String(100))
    email = db.Column(db.String(100))


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    # Core Data
    tool = db.Column(db.String(50)) # trivy, semgrep
    vuln_id = db.Column(db.String(100)) # CVE-XXX or Rule ID
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20)) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Location
    file_path = db.Column(db.String(255))
    line_number = db.Column(db.Integer, nullable=True)
    
    # Remediation
    fix_recommendation = db.Column(db.Text, nullable=True)
    
    # Mapping
    # Mapping
    owasp_category = db.Column(db.String(100), nullable=True) # OWASP Top 10 category

class QualityIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    # Core Data
    tool = db.Column(db.String(50)) # semgrep
    check_id = db.Column(db.String(100)) # rule id
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    
    # Quality Specifics
    # Category: Maintainability, Correctness, Performance, Complexity
    category = db.Column(db.String(50)) 
    severity = db.Column(db.String(20)) # ERROR, WARNING, INFO
    
    # Location
    file_path = db.Column(db.String(255))
    line_number = db.Column(db.Integer, nullable=True)
    
    # Estimates
    effort_minutes = db.Column(db.Integer, default=5) # Estimated time to fix
