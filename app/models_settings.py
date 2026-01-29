from app.models import db

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # Core Config
    company_name = db.Column(db.String(100), default='Spectra')
    language = db.Column(db.String(10), default='fr') # fr, en
    
    # GitHub Config
    github_pat = db.Column(db.String(255), nullable=True)
    
    # AI Config
    ai_provider = db.Column(db.String(50), default='gemini') # gemini, openai, openrouter, ollama
    ai_api_key = db.Column(db.String(255), nullable=True)
    ai_model = db.Column(db.String(100), default='gemini-pro')
    ai_api_url = db.Column(db.String(255), nullable=True) # For Ollama or custom endpoints
