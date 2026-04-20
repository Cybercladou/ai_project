import os

# WebAuthn Relying Party settings
# RP_ID must be your domain (no protocol, no port).
# For local dev: "localhost"
# For production: "yourdomain.com"
# RP_ID = os.getenv("RP_ID", "localhost")
# RP_ID = os.getenv("RP_ID", "mower-return-wand.ngrok-free.dev")
RP_ID = os.getenv("RP_ID", "bug-free-enigma-w9qpv976g5729pv7-8000.app.github.dev")
RP_NAME = os.getenv("RP_NAME", "台中旅遊愛好者協會")

# The full origin the browser uses to reach your site.
# For local dev: "http://localhost:8000"
# For production: "https://yourdomain.com"
# ORIGIN = os.getenv("ORIGIN", "http://localhost:8000")
# ORIGIN = os.getenv("ORIGIN", "https://mower-return-wand.ngrok-free.dev")
ORIGIN = os.getenv("ORIGIN", "https://bug-free-enigma-w9qpv976g5729pv7-8000.app.github.dev")

# JWT settings — set a long random secret in production
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-to-a-long-random-string-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24
