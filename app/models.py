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
    
    # Relationships
    repositories = db.relationship('Repository', backref='project', lazy=True, cascade="all, delete-orphan")
    scans = db.relationship('Scan', backref='project', lazy=True, cascade="all, delete-orphan")

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False) 
    
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
    
    # Relationships
    results = db.relationship('Vulnerability', backref='scan', lazy=True, cascade="all, delete-orphan")
    quality_issues = db.relationship('QualityIssue', backref='scan', lazy=True, cascade="all, delete-orphan")

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
