from openai import OpenAI
from app.ai.base import BaseAIProvider

class OpenAICompatibleProvider(BaseAIProvider):
    def __init__(self, api_key, model, base_url=None):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url # Automatic for OpenAI if None
        )
        self.model = model
        
    def generate(self, prompt: str, system_instruction: str = None) -> str:
        messages = []
        
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
            
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI Compatible API Error: {e}")
            raise e
