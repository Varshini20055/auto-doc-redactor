"""
Convenience entry point — always binds to 0.0.0.0 so both
IPv4 (127.0.0.1) and IPv6 (::1) localhost resolve correctly.

Usage:
    cd backend
    python run.py
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
