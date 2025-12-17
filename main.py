import sys
import asyncio
import uvicorn
import os
from dotenv import load_dotenv
from starlette.middleware.sessions import SessionMiddleware
load_dotenv()
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import psycopg
from psycopg.rows import dict_row
from psycopg.errors import IntegrityError
from passlib.context import CryptContext
import pandas as pd
import io
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

app = FastAPI()

# --- SETUP ---
app.add_middleware(SessionMiddleware, secret_key="qwertyuiopasdfghjklzxcvbnm", max_age=None, same_site='lax')
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
templates = Jinja2Templates(directory="templates")
DB_URI = os.getenv("DB_URL") 

if not DB_URI:
    raise ValueError("DB_URL tidak ditemukan di file .env!")

# --- DEFINISI MAPPING POLICY GROUP (Hardcoded ID) ---
POLICY_GROUP_MAPPING = {
    "NON AKS": (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,23,24,31,32,33,35,36,37,41,42,43,44,61,62,63,64,65,66,67,68,69,70,71,72,81,82,83,84,85,92,95,96,86),
    "AKS": (21,38,45,46,47,48,51,52,53,54,55,56,57,58,59,60,73,74,75,76,77,78,80,97,87,88),
    "AKS Non Konsumtif": (21,38,45,46,47,48,51,52,53,54,55,56,57,58,60,73,74,75,76,77,78,80,97)
}

async def get_async_db_connection():
    # Ini membuat koneksi secara asynchronous
    conn = await psycopg.AsyncConnection.connect(DB_URI, row_factory=dict_row)
    return conn

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def show_login_page(request: Request):
    # Cek jika user sudah login, langsung lempar ke menu utama
    if request.session.get("user"):
        return RedirectResponse(url="/main_menu", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_user(request: Request, username: str = Form(...), password: str = Form(...)):
    """ Route Login dengan Session """
    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = await cur.fetchone() 
            
                if user and pwd_context.verify(password, user['password_hash']):
                    # --- SIMPAN SESI DI SINI ---
                    request.session["user"] = user['username'] 
                    request.session["role"] = user['role']
                    
                    # Redirect bersih tanpa parameter username di URL
                    return RedirectResponse(url="/main_menu?init_session=1", status_code=303)
            
                return templates.TemplateResponse("login.html", {"request": request, "error": "Login gagal."})
    except Exception as e:
        return templates.TemplateResponse("login.html", {"request": request, "error": f"Error: {e}"})

@app.get("/register", response_class=HTMLResponse)
async def show_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_user(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        hashed_password = pwd_context.hash(password)
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'user')",
                    (username, hashed_password)
                )
                await conn.commit()

        return templates.TemplateResponse("login.html", {
            "request": request, 
            "success": "Registration successful! Please login." 
        })

    except IntegrityError:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Username already exists."
        })
        
    except Exception as e:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": f"Error: {e}"
        })

@app.get("/main_menu", response_class=HTMLResponse)
async def main_menu(request: Request): # Hapus parameter username: str = Query(...)
    """ Halaman Utama """
    # --- CEK SESI ---
    username = request.session.get("user")
    role = request.session.get("role")

    if not username:
        return RedirectResponse(url="/", status_code=303) # Tendang ke login jika belum login

    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT status, SUM(premi_total) as total FROM data_polis GROUP BY status")
                data_status = await cur.fetchall()
                
                await cur.execute("SELECT cc_code, SUM(premi_total) as total FROM data_polis GROUP BY cc_code ORDER BY total DESC LIMIT 5")
                data_cabang = await cur.fetchall()

        status_labels = [row['status'] for row in data_status]
        status_values = [float(row['total']) if row['total'] else 0 for row in data_status]
        cabang_labels = [row['cc_code'] for row in data_cabang]
        cabang_values = [float(row['total']) if row['total'] else 0 for row in data_cabang]

        return templates.TemplateResponse("main_menu.html", {
            "request": request,
            "username": username,
            "role": role,
            "status_labels": status_labels,
            "status_values": status_values,
            "cabang_labels": cabang_labels,
            "cabang_values": cabang_values
        })

    except Exception as e:
        return f"Error loading main menu: {str(e)}"
    
# --- API BARU: SEARCH CUSTOMER (Untuk Tom Select) ---
@app.get("/api/customers")
async def search_customers(q: str = Query(..., min_length=2)): # Minimal ketik 2 huruf
    """
    API khusus untuk pencarian dinamis dropdown Customer.
    Hanya mengambil max 50 data yang sesuai keyword.
    """
    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                search_pattern = f"%{q}%"
                await cur.execute("SELECT ent_id, ent_name FROM prod_data_master WHERE ent_name ILIKE %s ORDER BY ent_name LIMIT 50", (search_pattern,))
                results = await cur.fetchall()
                formatted_results = [{"value": row["ent_id"], "text": row["ent_name"]} for row in results]
                return JSONResponse(content=formatted_results)
    except Exception as e:
        return JSONResponse(content=[], status_code=500)

@app.get("/premi_statistik", response_class=HTMLResponse)
async def premi_statistik(
    request: Request, 
    pol_no: Optional[str] = None, 
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None,
    policy_group: Optional[str] = None,
    business_type: Optional[str] = None,
    branch: Optional[str] = None,
    cob: Optional[List[int]] = Query(None),
    company_group: Optional[List[str]] = Query(None),
    customer: Optional[List[int]] = Query(None),
    limit: int = 25
):
    
    # --- CEK SESI ---
    username = request.session.get("user")
    role = request.session.get("role")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    
    try:
        # 1. Fetch COB List untuk dropdown
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                # Asumsi tabel prod_data_jenis punya kolom description
                await cur.execute("SELECT pol_type_id, description FROM prod_data_jenis ORDER BY description")
                cob_list = await cur.fetchall()

                # 2. Fetch Branch List (Data Cabang) - BARU
                await cur.execute("SELECT cc_code, description FROM prod_data_cabang ORDER BY description")
                branch_list = await cur.fetchall()

                await cur.execute("""
                    SELECT grups, grupsumbis 
                    FROM data_polis 
                    WHERE grups IS NOT NULL 
                    GROUP BY grups, grupsumbis 
                    ORDER BY grups ASC
                """)
                company_group_list = await cur.fetchall()

                preloaded_customers = []
                if customer:
                    await cur.execute(
                        "SELECT ent_id, ent_name FROM prod_data_master WHERE ent_id = ANY(%s)",
                        (customer,)
                    )
                    preloaded_customers = await cur.fetchall()

                # 2. Build Main Query
                sql_query = """
                    SELECT 
                        b.pol_no, 
                        b.order_no, 
                        b.nama, 
                        b.tgl_lahir, 
                        b.refd2 AS periode_awal, 
                        b.refd3 AS periode_akhir, 
                        b.tsi_obj_rev, 
                        b.premi_obj_rev,
                        a.status -- Status tetap diambil dari data_polis untuk pewarnaan baris (opsional)
                    FROM data_debitur b
                    INNER JOIN data_polis a ON a.pol_id = b.pol_id
                    WHERE b.status IN ('POLICY', 'ENDORSE', 'RENEWAL')
                    AND b.delete_f IS NULL
                """
                
                params = []

                if pol_no:
                    # Filter hanya ke kolom b.pol_no (data_debitur)
                    sql_query += " AND b.pol_no ILIKE %s"
                    params.append(f"%{pol_no}%")
                
                if start_date:
                    sql_query += " AND a.policy_date >= %s"
                    params.append(start_date)

                if end_date:
                    sql_query += " AND a.policy_date <= %s"
                    params.append(end_date)

                # Filter Policy Group
                if policy_group and policy_group in POLICY_GROUP_MAPPING:
                    id_list = list(POLICY_GROUP_MAPPING[policy_group])
                    sql_query += " AND a.pol_type_id = ANY(%s)"
                    params.append(id_list)

                # Filter Business Type
                if business_type == "Unit AKS":
                    sql_query += " AND a.cc_code <> '80'"
                elif business_type == "Unit NON AKS":
                    sql_query += " AND a.cc_code = '80'"

                # --- FILTER BRANCH ---
                if branch:
                    sql_query += " AND a.cc_code = %s"
                    params.append(branch)

                # Filter Multi COB
                if cob:
                    sql_query += " AND a.pol_type_id = ANY(%s)"
                    params.append(cob)

                if customer:
                    sql_query += " AND a.idsumbis = ANY(%s)"
                    params.append(customer)

                sql_query += " ORDER BY b.pol_no, b.order_no LIMIT %s"
                params.append(limit)

                await cur.execute(sql_query, params)
                data_polis = await cur.fetchall()

        return templates.TemplateResponse("premi_statistik.html", {
            "request": request,
            "username": username,
            "role": role, 
            "report_data": data_polis,
            "pol_no": pol_no or "", 
            "start_date": start_date or "", "end_date": end_date or "",
            "policy_group": policy_group or "",
            "business_type": business_type or "",
            "branch": branch or "", 
            "branch_list": branch_list,
            "cob_list": cob_list,
            "selected_cob": cob or [],
            "company_group_list": company_group_list,
            "selected_company_group": company_group or [],
            "preloaded_customers": preloaded_customers, 
            "selected_customer_ids": customer or [],
            "limit": limit
        })

    except Exception as e:
        return f"Error loading dashboard: {str(e)}"

# --- QUERY REPORT LENGKAP ---
QUERY_REPORT = """
    SELECT 
        a.period_start, a.period_end, a.policy_date, a.status,
        ';' || a.pol_no AS pol_no,
        a.grupmarketer, a.marketer, a.sumbis as sumbis_name, a.cust_name, a.ccy_rate,
        b.ins_pol_obj_id, b.nama, b.coverage, a.kreasi_type_desc, b.ref2, b.kode_pos,
        b.kriteria, b.risk_class, b.tgl_lahir, b.refd2, b.refd3, b.ins_risk_cat_code,
        b.tsi_obj_rev AS tsi_obj, b.tsiko_obj, b.premi_obj_rev AS premi_obj,
        b.premiko_obj, b.diskonko_obj, b.commko_obj, b.bfeeko_obj, b.hfeeko_obj,
        b.disc_obj, b.komisi_obj, b.bfee_obj, b.hfee_obj, b.fbase_obj, b.ppn_obj,
        b.building, b.machine, b.stock, b.other, b.tsi_or, b.premi_or, b.komisi_or,
        b.tsi_bppdan, b.premi_bppdan, b.komisi_bppdan, b.tsi_kscbi, b.premi_kscbi,
        b.komisi_kscbi, b.tsi_spl, b.premi_spl, b.komisi_spl, b.tsi_fac, b.premi_fac,
        b.komisi_fac, b.tsi_qs, b.premi_qs, b.komisi_qs, b.tsi_park, b.premi_park,
        b.komisi_park, b.tsi_faco, b.premi_faco, b.komisi_faco, b.tsi_faco1,
        b.premi_faco1, b.komisi_faco1, b.tsi_faco2, b.premi_faco2, b.komisi_faco2,
        b.tsi_faco3, b.premi_faco3, b.komisi_faco3, b.tsi_jp, b.premi_jp, b.komisi_jp,
        b.no_pk, b.desc1, a.endorse_notes, a.cc_code as kode_cabang,
        a.category1 as sumbis_kategori, a.cc_code_source as kode_cabang_penerbit,
        a.pol_type_id as kode_cob, 
        c.description as cob_description,
        a.region_id_source AS region_source
    FROM data_debitur b
    INNER JOIN data_polis a ON a.pol_id = b.pol_id
    LEFT JOIN prod_data_jenis c ON a.pol_type_id = c.pol_type_id
    WHERE b.status IN ('POLICY', 'ENDORSE', 'RENEWAL')
    AND b.delete_f IS NULL
"""
@app.get("/download_report")
async def download_report(
    request: Request, 
    pol_no: Optional[str] = None, 
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None,
    policy_group: Optional[str] = None,
    business_type: Optional[str] = None,
    branch: Optional[str] = None,
    cob: Optional[List[int]] = Query(None),
    company_group: Optional[List[str]] = Query(None),
    customer: Optional[List[int]] = Query(None)
):
    
    if not request.session.get("user"):
        return RedirectResponse(url="/", status_code=303)
    """
    Route Download (CSV Version)
    """
    try:
        if await request.is_disconnected():
            return "Request cancelled"

        final_query = QUERY_REPORT
        params = []

        if pol_no:
            final_query += " AND b.pol_no ILIKE %s"
            params.append(f"%{pol_no}%")
        
        if start_date:
            final_query += " AND a.policy_date >= %s"
            params.append(start_date)

        if end_date:
            final_query += " AND a.policy_date <= %s"
            params.append(end_date)
        
        if policy_group and policy_group in POLICY_GROUP_MAPPING:
            id_list = list(POLICY_GROUP_MAPPING[policy_group]) # Convert tuple ke list
            final_query += " AND a.pol_type_id = ANY(%s)" # Syntax Postgres untuk array check
            params.append(id_list)

        # FILTER BUSINESS TYPE DOWNLOAD
        if business_type == "Unit AKS":
            final_query += " AND a.cc_code <> '80'"
        elif business_type == "Unit NON AKS":
            final_query += " AND a.cc_code = '80'"

        # --- FILTER BRANCH DOWNLOAD ---
        if branch:
            final_query += " AND a.cc_code = %s"
            params.append(branch)

        if cob:
            final_query += " AND a.pol_type_id = ANY(%s)"
            params.append(cob)

        if company_group:
            final_query += " AND a.grups = ANY(%s)"
            params.append(company_group)

        if customer:
            final_query += " AND a.idsumbis = ANY(%s)"
            params.append(customer)
            
        # EKSEKUSI DB (ASYNC)
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(final_query, params)
                if cur.description:
                    columns = [col.name for col in cur.description] 
                    data = await cur.fetchall()
                else:
                    columns = []
                    data = []

        # PROSES CSV (Blocking CPU task, run in thread)
        def process_csv():
            df = pd.DataFrame(data, columns=columns)
            
            # --- FORMAT TANGGAL ---
            target_date_cols = ['period_start', 'period_end', 'policy_date', 'tgl_lahir', 'refd2', 'refd3']
            for col in target_date_cols:
                if col in df.columns:
                    df[col] = pd.to_datetime(df[col], errors='coerce')
                    df[col] = df[col].dt.strftime('%Y-%m-%d').fillna('')

            # --- GENERATE CSV ---
            output = io.StringIO()
            df.to_csv(output, index=False)
            return output.getvalue()

        csv_content = await asyncio.to_thread(process_csv)
        
        # --- LOGIKA PENAMAAN FILE ---
        tgl_awal = start_date if start_date else "ALL"
        tgl_akhir = end_date if end_date else "ALL"
        filename = f"premi_statistik_{tgl_awal}_sd_{tgl_akhir}.csv"
        
        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
        
        return StreamingResponse(
            iter([csv_content]), 
            headers=headers, 
            media_type='text/csv'
        )

    except asyncio.CancelledError:
        print("⚠️ User memutus koneksi. Download dibatalkan.")
        raise 

    except Exception as e:
        print(f"Error: {e}")
        return f"Terjadi kesalahan: {str(e)}"
    
# --- [TAMBAHKAN INI DI main.py] ---

@app.get("/klaim_statistik", response_class=HTMLResponse)
async def klaim_statistik(
    request: Request, 
    username: str = Query("User"), 
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None,
    policy_group: Optional[str] = None,
    business_type: Optional[str] = None,
    branch: Optional[str] = None,
    cob: Optional[List[int]] = Query(None),
    company_group: Optional[List[str]] = Query(None),
    company_group_marketer: Optional[List[str]] = Query(None),
    marketer: Optional[List[str]] = Query(None),
    customer: Optional[List[int]] = Query(None),
    limit: int = 25
):
    
    # --- CEK SESI ---
    username = request.session.get("user")
    role = request.session.get("role")

    if not username:
        return RedirectResponse(url="/", status_code=303)
    
    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                # 1. Fetch Dropdown Data
                await cur.execute("SELECT pol_type_id, description FROM prod_data_jenis ORDER BY description")
                cob_list = await cur.fetchall()

                await cur.execute("SELECT cc_code, description FROM prod_data_cabang ORDER BY description")
                branch_list = await cur.fetchall()

                # 2. Fetch Company Group (Customer)
                await cur.execute("""
                    SELECT grups, grupsumbis 
                    FROM data_klaim 
                    WHERE grups IS NOT NULL 
                    GROUP BY grups, grupsumbis 
                    ORDER BY grups ASC
                """)
                company_group_list = await cur.fetchall()

                # 3. Fetch Company Group MARKETER
                await cur.execute("""
                    SELECT grupm, grupmarketer 
                    FROM data_klaim 
                    WHERE grupm IS NOT NULL 
                    GROUP BY grupm, grupmarketer 
                    ORDER BY grupm ASC
                """)
                company_group_marketer_list = await cur.fetchall()

                # 4. Fetch MARKETER List
                await cur.execute("""
                    SELECT idmarketer, marketer
                    FROM data_klaim
                    WHERE idmarketer IS NOT NULL
                    GROUP BY idmarketer, marketer
                    ORDER BY idmarketer ASC
                """)
                marketer_list = await cur.fetchall()

                # 5. Preload Customer (jika ada yang dipilih)
                preloaded_customers = []
                if customer:
                    await cur.execute(
                        "SELECT ent_id, ent_name FROM prod_data_master WHERE ent_id = ANY(%s)",
                        (customer,)
                    )
                    preloaded_customers = await cur.fetchall()

                # 2. Build Query untuk Data Klaim
                # Note: Kolom yang ditampilkan di SELECT disesuaikan untuk tampilan tabel HTML
                # Jika nama kolom di tabel data_klaim berbeda, mohon sesuaikan bagian ini.
                sql_query = """
                    SELECT 
                        dla_no, 
                        pol_no, 
                        order_no, 
                        nama, 
                        tgl_lahir, 
                        refd2, -- tgl_awal
                        refd3, -- tgl_akhir
                        claim_amount, -- nilai klaim
                        status
                    FROM data_klaim 
                    WHERE 1=1 
                """
                params = []

                # Filter: Approve Date (Start)
                if start_date:
                    sql_query += " AND approved_date >= %s"
                    params.append(start_date)

                # Filter: Approve Date (End)
                if end_date:
                    sql_query += " AND approved_date <= %s"
                    params.append(end_date)

                # Filter: Policy Group (Mapping sama dengan premi)
                if policy_group and policy_group in POLICY_GROUP_MAPPING:
                    id_list = list(POLICY_GROUP_MAPPING[policy_group])
                    sql_query += " AND pol_type_id = ANY(%s)"
                    params.append(id_list)

                # Filter: Business Type (cc_code)
                if business_type == "Unit AKS":
                    sql_query += " AND cc_code <> '80'"
                elif business_type == "Unit NON AKS":
                    sql_query += " AND cc_code = '80'"

                # Filter: Branch (cc_code)
                if branch:
                    sql_query += " AND cc_code = %s"
                    params.append(branch)

                # Filter: COB (pol_type_id)
                if cob:
                    sql_query += " AND pol_type_id = ANY(%s)"
                    params.append(cob)

                # --- Filter Company Group ---
                if company_group:
                    sql_query += " AND grups = ANY(%s)"
                    params.append(company_group)

                if company_group_marketer:
                    sql_query += " AND grupm = ANY(%s)"
                    params.append(company_group_marketer)

                # --- Filter Marketer Logic ---
                if marketer:
                    sql_query += " AND idmarketer = ANY(%s)"
                    params.append(marketer)

                # Filter Customer
                if customer:
                    # Asumsi kolom relasi customer di data_klaim bernama 'idsumbis' (sesuaikan jika 'ent_id' atau lainnya)
                    sql_query += " AND idsumbis = ANY(%s)" 
                    params.append(customer)

                # Pengurutan Data
                sql_query += " ORDER BY dla_no, pol_no, order_no LIMIT %s"
                params.append(limit)

                await cur.execute(sql_query, params)
                data_klaim = await cur.fetchall()

        return templates.TemplateResponse("klaim_statistik.html", {
            "request": request, 
            "username": username,
            "role": role, 
            "report_data": data_klaim,
            "start_date": start_date or "", "end_date": end_date or "",
            "policy_group": policy_group or "",
            "business_type": business_type or "",
            "branch": branch or "", 
            "branch_list": branch_list,
            "cob_list": cob_list,
            "selected_cob": cob or [],
            "company_group_list": company_group_list, 
            "selected_company_group": company_group or [],
            "company_group_marketer_list": company_group_marketer_list,
            "selected_company_group_marketer": company_group_marketer or [],
            "marketer_list": marketer_list,
            "selected_marketer": marketer or [],
            "preloaded_customers": preloaded_customers,
            "selected_customer_ids": customer or [],
            "limit": limit
        })

    except Exception as e:
        return f"Error loading klaim statistik: {str(e)}"

@app.get("/download_claim_report")
async def download_claim_report(
    request: Request, 
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None,
    policy_group: Optional[str] = None,
    business_type: Optional[str] = None,
    branch: Optional[str] = None,
    cob: Optional[List[int]] = Query(None),
    company_group: Optional[List[str]] = Query(None),
    company_group_marketer: Optional[List[str]] = Query(None),
    marketer: Optional[List[str]] = Query(None),
    customer: Optional[List[int]] = Query(None)
):
    
    if not request.session.get("user"):
        return RedirectResponse(url="/", status_code=303)
    
    """
    Download Excel (CSV) untuk Data Klaim (SELECT *)
    """
    try:
        if await request.is_disconnected():
            return "Request cancelled"

        final_query = """
                    SELECT 
                    cc_code, pol_type_id, policy_date, approved_date, claim_date, claim_propose_date, pla_date, dla_date, pol_id, 
                    ins_pol_obj_id, ';' || pol_no as pol_no, ';' || sub_polno as sub_polno, pla_no, dla_no, cust_name, nama, tgl_lahir, ccy_rate, ccy_rate_claim, insured_amount, claim_amount, 
                    coins_amount, coins_name, cause_desc, klaimbruto, deductible, subrogasi, wreck, biayaadjuster, tjh, biayaderek, salvage, exgratiaklaim, bunga, 
                    santunankecelakaan, depresiasi, uangmukapremi, uangmukakomisi, interimpayment, penalty, jasabengkel, pajak, exgratiabebanunderwritinglainlain, feerecovery, 
                    biayasparepart, joinplacement, ppn, biayasurvey, ppntotal, cashcollateralsubrograsi, material, surveyadjusmentfee, expenses, vatfee, biayaadministrasimateraidll, 
                    kronologi, potensi_subro, receipt_date, receipt_no, tsi_or, premi_or, komisi_or, klaim_or, tsi_bppdan, premi_bppdan, komisi_bppdan, klaim_bppdan, tsi_kscbi, premi_kscbi, 
                    komisi_kscbi, klaim_kscbi, tsi_spl, premi_spl, komisi_spl, klaim_spl, tsi_fac, premi_fac, komisi_fac, klaim_fac, tsi_qs, premi_qs, komisi_qs, klaim_qs, tsi_park, 
                    premi_park, komisi_park, klaim_park, tsi_faco, premi_faco, komisi_faco, klaim_faco, tsi_faco1, premi_faco1, komisi_faco1, klaim_faco1, tsi_faco2, premi_faco2, komisi_faco2, 
                    klaim_faco2, tsi_faco3, premi_faco3, komisi_faco3, klaim_faco3, tsi_jp, premi_jp, komisi_jp, klaim_jp, tsi_facp, premi_facp, komisi_facp, klaim_facp, tsi_qskr, 
                    premi_qskr, komisi_qskr, klaim_qskr, payment_company_id, cc_code_source, region_id_source, region_id, claim_amount_est, claim_amount_approved, order_no, status, refd2, 
                    refd3, grups, grupsumbis, idsumbis, sumbis, grupm, grupmarketer, idmarketer, marketer, ins_pol_obj_ref_root_id, status_loss_id, nik_ktp, ccy, ccy_claim

                    FROM data_klaim 
                    WHERE 1=1 
                """
        
        params = []
        
        # --- LOGIKA FILTER (SAMA DENGAN VIEW) ---
        if start_date:
            final_query += " AND approved_date >= %s"
            params.append(start_date)

        if end_date:
            final_query += " AND approved_date <= %s"
            params.append(end_date)
        
        if policy_group and policy_group in POLICY_GROUP_MAPPING:
            id_list = list(POLICY_GROUP_MAPPING[policy_group])
            final_query += " AND pol_type_id = ANY(%s)"
            params.append(id_list)

        if business_type == "Unit AKS":
            final_query += " AND cc_code <> '80'"
        elif business_type == "Unit NON AKS":
            final_query += " AND cc_code = '80'"

        if branch:
            final_query += " AND cc_code = %s"
            params.append(branch)

        if cob:
            final_query += " AND pol_type_id = ANY(%s)"
            params.append(cob)

        if company_group:
            final_query += " AND grups = ANY(%s)"
            params.append(company_group)

        if company_group_marketer:
            final_query += " AND grupm = ANY(%s)"
            params.append(company_group_marketer)

        if marketer:
            final_query += " AND idmarketer = ANY(%s)"
            params.append(marketer)

        if customer:
            final_query += " AND idsumbis = ANY(%s)"
            params.append(customer)
        
        final_query += " ORDER BY dla_no, pol_no, order_no"

        # EKSEKUSI DB
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(final_query, params)
                if cur.description:
                    columns = [col.name for col in cur.description] 
                    data = await cur.fetchall()
                else:
                    columns = []
                    data = []

        # PROSES CSV
        def process_csv():
            df = pd.DataFrame(data, columns=columns)
            
            # Format tanggal umum jika ada kolom tanggal
            for col in df.columns:
                if 'date' in col.lower() or 'tgl' in col.lower():
                    df[col] = pd.to_datetime(df[col], errors='coerce')
                    df[col] = df[col].dt.strftime('%Y-%m-%d').fillna('')

            output = io.StringIO()
            df.to_csv(output, index=False)
            return output.getvalue()

        csv_content = await asyncio.to_thread(process_csv)
        
        filename = f"klaim_statistik_{datetime.now().strftime('%Y%m%d')}.csv"
        
        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
        
        return StreamingResponse(
            iter([csv_content]), 
            headers=headers, 
            media_type='text/csv'
        )

    except Exception as e:
        return f"Terjadi kesalahan: {str(e)}"
    
# --- MANAJEMEN USER ROUTES ---

@app.get("/manajemen_user", response_class=HTMLResponse)
async def page_manajemen_user(request: Request):
    # 1. Cek Sesi & Role Admin
    username = request.session.get("user")
    role = request.session.get("role")
    
    if not username:
        return RedirectResponse(url="/", status_code=303)
    
    if role != 'admin':
        return HTMLResponse("<h1>Akses Ditolak: Halaman ini hanya untuk Admin.</h1>", status_code=403)

    # 2. Ambil Daftar User
    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
                users = await cur.fetchall()
        
        return templates.TemplateResponse("manajemen_user.html", {
            "request": request,
            "username": username,
            "role": role, # Kirim role ke template untuk sidebar
            "users": users
        })
    except Exception as e:
        return f"Error: {e}"

@app.post("/manajemen_user/add")
async def add_user(request: Request, new_username: str = Form(...), new_password: str = Form(...), new_role: str = Form(...)):
    # Cek Admin
    if request.session.get("role") != 'admin': return RedirectResponse(url="/main_menu", status_code=303)
    
    try:
        hashed_pwd = pwd_context.hash(new_password)
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                    (new_username, hashed_pwd, new_role)
                )
                await conn.commit()
        return RedirectResponse(url="/manajemen_user", status_code=303)
    except Exception as e:
        return f"Gagal menambah user: {e}"

@app.post("/manajemen_user/delete")
async def delete_user(request: Request, user_id: int = Form(...)):
    # Cek Admin
    if request.session.get("role") != 'admin': return RedirectResponse(url="/main_menu", status_code=303)
    
    # Cegah hapus diri sendiri (opsional tapi disarankan)
    # Anda bisa cek user_id vs session username di db

    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                await conn.commit()
        return RedirectResponse(url="/manajemen_user", status_code=303)
    except Exception as e:
        return f"Gagal menghapus user: {e}"

@app.post("/manajemen_user/update_role")
async def update_user_role(request: Request, user_id: int = Form(...), new_role: str = Form(...)):
    # Cek Admin
    if request.session.get("role") != 'admin': return RedirectResponse(url="/main_menu", status_code=303)

    try:
        async with await get_async_db_connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
                await conn.commit()
        return RedirectResponse(url="/manajemen_user", status_code=303)
    except Exception as e:
        return f"Gagal update role: {e}"
    
class ChatRequest(BaseModel):
    message: str

@app.post("/api/chat")
async def chat_endpoint(chat_req: ChatRequest):
    """
    Chatbot Level Dasar (Rule-Based).
    Sangat ringan, tidak butuh GPU/RAM besar, respon instan.
    """
    user_msg = chat_req.message.lower().strip()
    
    # --- LOGIKA JAWABAN (Brain) ---
    response_text = ""
    redirect_url = None # Opsional: jika ingin mengarahkan user ke halaman lain

    if "halo" in user_msg or "hi" in user_msg or "selamat" in user_msg:
        response_text = "Halo! Saya asisten virtual AIS. Ada yang bisa saya bantu terkait navigasi atau fitur?"
    
    elif "premi" in user_msg:
        response_text = "Untuk melihat laporan Premi, Anda bisa mengakses menu 'Premi Statistik'. Di sana Anda bisa memfilter berdasarkan Cabang, COB, dan lainnya."
        redirect_url = "/premi_statistik"
        
    elif "klaim" in user_msg:
        response_text = "Data Klaim tersedia di menu 'Klaim Statistik'. Anda dapat melihat status klaim dan mendownload laporannya."
        redirect_url = "/klaim_statistik"
        
    elif "risk" in user_msg or "profil" in user_msg:
        response_text = "Fitur Risk Profile saat ini masih dalam pengembangan. Nantikan update selanjutnya!"
        
    elif "admin" in user_msg or "user" in user_msg:
        response_text = "Manajemen User hanya bisa diakses oleh akun dengan role Admin melalui menu Pengaturan > Manajemen User."
        
    elif "keluar" in user_msg or "logout" in user_msg:
        response_text = "Anda bisa logout dengan menekan tombol merah di pojok kanan atas, atau klik link di bawah ini."
        redirect_url = "/logout"
        
    elif "bantuan" in user_msg or "help" in user_msg:
        response_text = "Coba ketik kata kunci seperti: 'Premi', 'Klaim', 'Admin', atau 'Logout'."
        
    else:
        response_text = "Maaf, saya tidak mengerti. Coba gunakan kata kunci sederhana seperti 'Premi', 'Klaim', atau 'Admin'."

    return JSONResponse(content={
        "response": response_text,
        "redirect_url": redirect_url
    })

# --- ROUTE LOGOUT ---
@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

if __name__ == "__main__":
    # Karena kita menjalankan via 'python main.py', kode fix Windows di paling atas
    # akan dieksekusi SEBELUM Uvicorn menyalakan event loop-nya.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)