#!/usr/bin/env python3
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8501))
    workshop_url = os.environ.get("WORKSHOP_URL", "http://localhost")
    print(f"\nRisk Analyzer Dashboard: {workshop_url}/app/{port}/\n")
    uvicorn.run("src.web.app:app", host="0.0.0.0", port=port, reload=True)
