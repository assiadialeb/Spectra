from app import create_app, db
from sqlalchemy import text

app = create_app()
with app.app_context():
    with db.engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE settings ADD COLUMN company_name VARCHAR(100)"))
            print("Added company_name column.")
        except Exception as e:
            print(f"company_name column might exist: {e}")
            
        try:
            conn.execute(text("ALTER TABLE settings ADD COLUMN language VARCHAR(10)"))
            print("Added language column.")
        except Exception as e:
            print(f"language column might exist: {e}")
        
        conn.commit()
