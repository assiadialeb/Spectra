import google.generativeai as genai
from app.ai.base import BaseAIProvider
import os

class GeminiProvider(BaseAIProvider):
    def __init__(self, api_key, model='gemini-1.5-pro'):
        self.api_key = api_key
        self.model_name = model
        genai.configure(api_key=self.api_key)
        
    def generate(self, prompt: str, system_instruction: str = None) -> str:
        try:
            # Gemini supports system instructions in the model config or prompt
            # For simplicity, we can prepend it if the lib doesn't support it directly in current version
            # But recent versions do:
            model = genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=system_instruction
            )
            
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Gemini API Error: {e}")
            raise e
