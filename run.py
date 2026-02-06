import sys
import asyncio
import uvicorn

# 1. PAKSA SETTINGAN LOOP SEBELUM IMPORT APAPUN
# Ini mencegah Windows menggunakan ProactorEventLoop yang bikin error
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# 2. IMPORT APP DARI MAIN
# Pastikan main.py sudah bersih dari uvicorn.run di dalamnya
from main import app

if __name__ == "__main__":
    print("🚀 Menjalankan AIS System (Mode Dev - No Reload)...")
    
    # 3. JALANKAN SERVER
    # reload=False : WAJIB False di Windows agar settingan loop tidak reset
    # host="127.0.0.1" : Gunakan localhost standar
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)