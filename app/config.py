"""Runtime configuration."""

import os

PLATFORM_NAME = "Code Agent"
PLATFORM_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

LOCAL_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://127.0.0.1:11434").rstrip("/")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "local-llm")
LOCAL_LLM_TIMEOUT = int(os.getenv("LOCAL_LLM_TIMEOUT", "300"))
LOCAL_LLM_MAX_TOKENS = int(os.getenv("LOCAL_LLM_MAX_TOKENS", "26000"))
LOCAL_LLM_TEMPERATURE = float(os.getenv("LOCAL_LLM_TEMPERATURE", "0.1"))

API_KEY = os.getenv("API_KEY", "")
MAX_STEPS = int(os.getenv("MAX_STEPS", "50"))
RETRY_ON_PARSE_FAIL = int(os.getenv("PARSE_RETRIES", "1"))
RETRY_DELAY_SECONDS = float(os.getenv("RETRY_DELAY", "2"))
AGENT_MAX_TOOL_RESULT = int(os.getenv("MAX_TOOL_RESULT", "8000"))
AGENT_MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.3"))

LOG_DIR = os.getenv("LOG_DIR", "logs")
REPORT_OUTPUT_DIR = os.getenv("REPORT_DIR", "reports")

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_CACHE_DIR = os.getenv("NVD_CACHE_DIR", "data/nvd_cache")
NVD_CACHE_EXPIRY = int(os.getenv("NVD_CACHE_EXPIRY", "604800"))
NVD_TIMEOUT = int(os.getenv("NVD_TIMEOUT", "30"))
NVD_MAX_RESULTS = int(os.getenv("NVD_MAX_RESULTS", "50"))

KALI_WORKER_URL = os.getenv("KALI_WORKER_URL", "http://127.0.0.1:8082").rstrip("/")
