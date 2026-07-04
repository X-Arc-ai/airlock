import os
# WHERE gemma runs (hosted / hetzner / M1) and WHICH size — the two knobs.
MODEL     = os.environ.get("AIRLOCK_MODEL", "gemma3:12b-it-qat")
MODEL_URL = os.environ.get("AIRLOCK_MODEL_URL", "http://127.0.0.1:11434")
EMBED_MODEL = os.environ.get("AIRLOCK_EMBED_MODEL", "embeddinggemma")
DB_PATH   = os.environ.get("AIRLOCK_DB", "airlock.db")
# quarantine when decision==quarantine OR (attack-family match with score>=this)
FAMILY_THRESHOLD = float(os.environ.get("AIRLOCK_FAMILY_THRESHOLD", "0.72"))
PROXY_PORT = int(os.environ.get("AIRLOCK_PROXY_PORT", "8899"))
UI_PORT    = int(os.environ.get("AIRLOCK_UI_PORT", "8787"))
