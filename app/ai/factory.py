from app.models_settings import Settings
from app.ai.gemini import GeminiProvider
from app.ai.openai_provider import OpenAICompatibleProvider

class AIFactory:
    @staticmethod
    def create_provider():
        """
        Creates and returns an AI provider instance based on database settings.
        """
        settings = Settings.query.first()
        
        # Defaults
        provider_name = 'gemini'
        api_key = None
        model = 'gemini-1.5-pro'
        api_url = None
        
        if settings:
            provider_name = settings.ai_provider or 'gemini'
            api_key = settings.ai_api_key
            model = settings.ai_model or 'gemini-1.5-pro'
            api_url = settings.ai_api_url
            
            # Sanitize empty string to None
            if isinstance(api_url, str) and not api_url.strip():
                api_url = None
            
        print(f"Initializing AI Provider: {provider_name}, Model: {model}")

        if provider_name == 'gemini':
            if not api_key:
                raise ValueError("API Key is required for Gemini.")
            return GeminiProvider(api_key=api_key, model=model)
            
        elif provider_name in ['openai', 'openrouter', 'ollama']:
            # Handle specific URLs
            if provider_name == 'openrouter' and not api_url:
                api_url = "https://openrouter.ai/api/v1"
            elif provider_name == 'ollama' and not api_url:
                api_url = "http://localhost:11434/v1"
            
            # OpenAI lib handles standard OpenAI URL if api_url is None
            
            if provider_name != 'ollama' and not api_key:
                 raise ValueError(f"API Key is required for {provider_name}.")
            
            # Ollama might allow empty key, OpenAI lib needs string though
            if provider_name == 'ollama' and not api_key:
                api_key = "ollama" # Dummy key often needed
                
            return OpenAICompatibleProvider(api_key=api_key, model=model, base_url=api_url)
            
        else:
            raise ValueError(f"Unsupported AI provider: {provider_name}")
