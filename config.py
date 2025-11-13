# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env into environment variables

OPENAI_API_KEY = "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"

if not OPENAI_API_KEY:
    raise RuntimeError(
        ""
    )
