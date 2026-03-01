import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import os
import smtplib
import threading
import webbrowser
import subprocess
import platform
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import urllib.request
import json
try:
    import pywhatkit
    WHATSAPP_AVAILABLE = True
except ImportError:
    WHATSAPP_AVAILABLE = False

# ─────────────────────────────────────────
#  CONFIGURATION 
# ─────────────────────────────────────────
SENDER_EMAIL    = "your_email@gmail.com"      # Your Gmail address
SENDER_PASSWORD = "your_app_password"         # Gmail App Password

# WhatsApp config – numbers must include country code, e.g. "+919876543210"
WHATSAPP_ENABLED = True   # Set False to disable WhatsApp alerts
# ─────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME  = os.path.join(BASE_DIR, "sheild_v2.db")

# ══════════════════════════════════════════════════════
#  THEME  –  Deep-crimson guardian palette
# ══════════════════════════════════════════════════════
C = {
    "bg":        "#0D0D14",   # near-black background
    "surface":   "#13131F",   # card surface
    "panel":     "#1A1A2E",   # sidebar / panel
    "accent":    "#E63462",   # vivid rose-red
    "accent2":   "#FF6B9D",   # soft pink
    "safe":      "#00D4AA",   # teal (safe / ok)
    "warn":      "#FF8C42",   # amber (warning)
    "text":      "#F0EAF8",   # off-white text
    "muted":     "#6B6B8A",   # muted label
    "border":    "#2A2A45",   # subtle border
    "sos_bg":    "#FF1744",   # emergency red
    "sos_ring":  "#FF6666",   # pulsing ring
}

FONT_TITLE  = ("Georgia", 26, "bold")
FONT_HEAD   = ("Georgia", 16, "bold")
FONT_SUB    = ("Helvetica", 11)
FONT_BODY   = ("Helvetica", 10)
FONT_SMALL  = ("Helvetica", 9)
FONT_MONO   = ("Courier", 9)
FONT_SOS    = ("Georgia", 22, "bold")
FONT_LABEL  = ("Helvetica", 10, "bold")

# ══════════════════════════════════════════════════════
#  DATABASE  –  single-connection, queue-serialised
# ══════════════════════════════════════════════════════
#
# ROOT CAUSE of "database is locked":
#   SQLite in its default journal mode only allows ONE writer at a time.
#   Opening a fresh connection from every thread causes collisions.
#
# SOLUTION: one persistent connection owned by a dedicated DB thread.
#   All queries are posted to a queue; the DB thread executes them one
#   by one and puts results back through a per-call Event + result slot.
#   This is 100% collision-free because SQLite is only ever touched from
#   a single thread.
#
# Stale lock files (from a previous crash) are deleted on startup.

import queue as _queue

_db_queue  = _queue.Queue()   # (query, params, fetch, result_box, event)

def _cleanup_stale_locks():
    """Remove leftover -journal / -wal / -shm files from a prior crash."""
    for suffix in ("-journal", "-wal", "-shm"):
        path = DB_NAME + suffix
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"[DB] Removed stale lock file: {path}")
        except Exception as exc:
            print(f"[DB] Could not remove {path}: {exc}")

def _db_worker():
    """Background thread that owns the one-and-only SQLite connection."""
    _cleanup_stale_locks()
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=DELETE;")  # simple, no WAL needed
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
    while True:
        item = _db_queue.get()
        if item is None:          # shutdown signal
            conn.close()
            break
        query, params, fetch, box, evt = item
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            if fetch == "one":
                box["result"] = cur.fetchone()
            elif fetch == "all":
                box["result"] = cur.fetchall()
            else:
                conn.commit()
                box["result"] = None
            box["error"] = None
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            box["result"] = None
            box["error"]  = exc
        finally:
            evt.set()

# Start the DB worker thread immediately (daemon so it dies with the app)
_db_thread = threading.Thread(target=_db_worker, daemon=True, name="DB-Worker")
_db_thread.start()

def db_query(query, params=(), fetch=None):
    """Post a query to the DB worker thread and wait for the result.
    Raises any exception the worker encountered."""
    box = {}
    evt = threading.Event()
    _db_queue.put((query, params, fetch, box, evt))
    evt.wait()                    # blocks calling thread until done
    if box.get("error"):
        raise box["error"]
    return box.get("result")

def setup_database():
    db_query("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        hashed_password TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    db_query("""CREATE TABLE IF NOT EXISTS emergency_contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT NOT NULL,
        contact_name TEXT NOT NULL,
        contact_phone TEXT NOT NULL,
        contact_email TEXT,
        relation TEXT DEFAULT 'Contact'
    )""")
    db_query("""CREATE TABLE IF NOT EXISTS sos_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT NOT NULL,
        location TEXT,
        latitude REAL,
        longitude REAL,
        timestamp TEXT,
        status TEXT DEFAULT 'SENT'
    )""")

# ══════════════════════════════════════════════════════
#  PASSWORD HELPERS
# ══════════════════════════════════════════════════════
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwd_hash.hex(), salt.hex()

def verify_password(stored_hash, stored_salt, password):
    salt = bytes.fromhex(stored_salt)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex() == stored_hash

# ══════════════════════════════════════════════════════
#  LIVE LOCATION (IP-based approximation)
# ══════════════════════════════════════════════════════
def get_live_location():
    try:
        url  = "http://ip-api.com/json/?fields=status,city,regionName,country,lat,lon,query"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            return {
                "city":    data.get("city", ""),
                "region":  data.get("regionName", ""),
                "country": data.get("country", ""),
                "lat":     data.get("lat", 0),
                "lon":     data.get("lon", 0),
                "ip":      data.get("query", ""),
                "display": f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
                "maps":    f"https://maps.google.com/?q={data.get('lat')},{data.get('lon')}"
            }
    except Exception:
        pass
    return {"display": "Location unavailable", "lat": 0, "lon": 0, "maps": ""}

# ══════════════════════════════════════════════════════
#  EMAIL / SOS
# ══════════════════════════════════════════════════════
def build_sos_email(user_name, user_phone, loc):
    maps_link = loc.get("maps", "")
    timestamp = datetime.now().strftime("%d %b %Y  %H:%M:%S")
    body = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨  SHEILD  |  EMERGENCY SOS ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{user_name} needs IMMEDIATE HELP!

📞  Phone     : {user_phone}
📍  Location  : {loc.get('display', 'Unknown')}
🗺️  Google Maps: {maps_link}
🕐  Time      : {timestamp}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is an automated emergency alert sent by the SHEILD Women Safety App.
Please contact the person immediately or call emergency services.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return body

def send_sos_email(to_email, user_name, user_phone, loc):
    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = to_email
        msg["Subject"] = f"🚨 EMERGENCY ALERT – {user_name} needs help! | SHEILD"
        msg.attach(MIMEText(build_sos_email(user_name, user_phone, loc), "plain"))
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {to_email}: {e}")
        return False

def build_whatsapp_sos_message(user_name, user_phone, loc):
    """Build a concise WhatsApp SOS message."""
    timestamp  = datetime.now().strftime("%d %b %Y  %H:%M:%S")
    maps_link  = loc.get("maps", "")
    msg = (
        f"🚨 *EMERGENCY SOS – SHEILD*\n\n"
        f"*{user_name}* needs IMMEDIATE HELP!\n\n"
        f"📞 Phone: {user_phone}\n"
        f"📍 Location: {loc.get('display', 'Unknown')}\n"
        f"🕐 Time: {timestamp}\n"
    )
    if maps_link:
        msg += f"🗺 Maps: {maps_link}\n"
    msg += "\nPlease contact them or call emergency services immediately!"
    return msg

def send_whatsapp_sos(contact_phone, user_name, user_phone, loc):
    """
    Send a WhatsApp message via pywhatkit (uses WhatsApp Web).
    contact_phone must include country code, e.g. '+919876543210'.
    Requires WhatsApp Web to be logged in on the default browser.
    """
    if not WHATSAPP_AVAILABLE:
        print("[WHATSAPP] pywhatkit not installed. Run: pip install pywhatkit")
        return False
    if not WHATSAPP_ENABLED:
        return False
    if not contact_phone or not contact_phone.startswith("+"):
        print(f"[WHATSAPP] Skipping {contact_phone}: number must include country code (+XX...)")
        return False
    try:
        message = build_whatsapp_sos_message(user_name, user_phone, loc)
        now = datetime.now()
        # Schedule 2 minutes ahead to give WhatsApp Web time to open
        send_hour   = now.hour
        send_minute = now.minute + 2
        if send_minute >= 60:
            send_minute -= 60
            send_hour = (send_hour + 1) % 24
        pywhatkit.sendwhatmsg(
            contact_phone,
            message,
            send_hour,
            send_minute,
            wait_time=20,       # seconds to wait after opening WhatsApp Web
            tab_close=True,     # close tab after sending
            close_time=5
        )
        print(f"[WHATSAPP] Sent to {contact_phone}")
        return True
    except Exception as e:
        print(f"[WHATSAPP ERROR] {contact_phone}: {e}")
        return False

def trigger_sos(user_phone, user_name, status_callback=None):
    def _run():
        loc = get_live_location()
        db_query(
            "INSERT INTO sos_logs (user_phone, location, latitude, longitude, timestamp) VALUES (?,?,?,?,?)",
            (user_phone, loc.get("display",""), loc.get("lat",0), loc.get("lon",0), str(datetime.now()))
        )
        contacts = db_query(
            "SELECT contact_email, contact_name, contact_phone FROM emergency_contacts WHERE user_phone=?",
            (user_phone,), fetch="all"
        )
        email_sent = 0
        wa_sent    = 0
        for row in contacts:
            email, cname, cphone = row
            # Send email
            if email:
                ok = send_sos_email(email, user_name, user_phone, loc)
                if ok:
                    email_sent += 1
            # Send WhatsApp
            if cphone:
                # Ensure country code present; if user stored 10-digit Indian number, auto-prepend +91
                wa_phone = cphone.strip()
                if wa_phone.isdigit() and len(wa_phone) == 10:
                    wa_phone = "+91" + wa_phone
                elif not wa_phone.startswith("+"):
                    wa_phone = "+" + wa_phone
                ok_wa = send_whatsapp_sos(wa_phone, user_name, user_phone, loc)
                if ok_wa:
                    wa_sent += 1
        if status_callback:
            status_callback(email_sent, wa_sent, loc.get("display","Unknown"))
    threading.Thread(target=_run, daemon=True).start()

# ══════════════════════════════════════════════════════
#  PHONE CALL HELPER
# ══════════════════════════════════════════════════════
def make_call(number):
    system = platform.system()
    if system == "Windows":
        os.startfile(f"tel:{number}")
    elif system == "Darwin":
        subprocess.Popen(["open", f"tel:{number}"])
    else:
        # Linux – try xdg-open then webbrowser
        try:
            subprocess.Popen(["xdg-open", f"tel:{number}"])
        except Exception:
            webbrowser.open(f"tel:{number}")

# ══════════════════════════════════════════════════════
#  REUSABLE UI HELPERS
# ══════════════════════════════════════════════════════
def styled_entry(parent, show="", width=28):
    e = tk.Entry(parent, show=show, width=width,
                 font=FONT_BODY, bg=C["border"], fg=C["text"],
                 insertbackground=C["accent"], relief="flat",
                 highlightthickness=1, highlightcolor=C["accent"],
                 highlightbackground=C["border"])
    return e

def styled_button(parent, text, command, bg=None, fg=C["text"],
                  font=None, width=None, pady=8, padx=16):
    bg   = bg or C["accent"]
    font = font or FONT_LABEL
    kw   = dict(text=text, command=command, bg=bg, fg=fg,
                font=font, relief="flat", cursor="hand2",
                activebackground=C["accent2"], activeforeground="white",
                padx=padx, pady=pady)
    if width:
        kw["width"] = width
    return tk.Button(parent, **kw)

def card_frame(parent, **kw):
    return tk.Frame(parent, bg=C["surface"],
                    highlightthickness=1,
                    highlightbackground=C["border"], **kw)

def divider(parent, pady=10):
    tk.Frame(parent, height=1, bg=C["border"]).pack(fill="x", pady=pady)

# ══════════════════════════════════════════════════════
#  REGISTER WINDOW
# ══════════════════════════════════════════════════════
class RegisterWindow:
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title("SHEILD – Create Account")
        self.win.geometry("480x680")
        self.win.configure(bg=C["bg"])
        self.win.resizable(False, False)
        self._build()

    def _build(self):
        w = self.win
        tk.Label(w, text="🛡 SHEILD", font=FONT_TITLE,
                 fg=C["accent"], bg=C["bg"]).pack(pady=(36,4))
        tk.Label(w, text="Create Your Safe Account",
                 font=FONT_SUB, fg=C["muted"], bg=C["bg"]).pack(pady=(0,24))

        card = card_frame(w)
        card.pack(fill="x", padx=36, pady=4)

        fields = [("Full Name","name",""),("Phone Number","phone",""),
                  ("Email Address","email",""),("Password","pwd","*"),
                  ("Confirm Password","cpwd","*")]
        self.vars = {}
        for label, key, show in fields:
            f = tk.Frame(card, bg=C["surface"])
            f.pack(fill="x", padx=20, pady=(14,0))
            tk.Label(f, text=label, font=FONT_SMALL,
                     fg=C["muted"], bg=C["surface"]).pack(anchor="w")
            e = styled_entry(f, show=show, width=36)
            e.pack(fill="x", pady=(4,0), ipady=8)
            self.vars[key] = e

        btn = styled_button(card, "CREATE ACCOUNT", self.register,
                            width=32, pady=10)
        btn.pack(pady=20)

    def register(self):
        v = {k: e.get().strip() for k, e in self.vars.items()}
        if not all(v.values()):
            messagebox.showerror("Missing Fields", "Please fill all fields.", parent=self.win)
            return
        if not v["phone"].isdigit() or len(v["phone"]) != 10:
            messagebox.showerror("Invalid Phone", "Enter a valid 10-digit phone number.", parent=self.win)
            return
        if v["pwd"] != v["cpwd"]:
            messagebox.showerror("Password Mismatch", "Passwords do not match.", parent=self.win)
            return
        hashed, salt = hash_password(v["pwd"])
        try:
            db_query(
                "INSERT INTO users (name,phone,email,hashed_password,salt) VALUES (?,?,?,?,?)",
                (v["name"], v["phone"], v["email"], hashed, salt)
            )
            messagebox.showinfo("Account Created",
                                "Your SHEILD account is ready.\nStay Safe! 🛡", parent=self.win)
            self.win.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Already Registered",
                                 "This phone number is already registered.", parent=self.win)

# ══════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════
class Dashboard:
    def __init__(self, user_phone, user_name):
        self.phone = user_phone
        self.name  = user_name
        self._sos_active = False

        self.win = tk.Toplevel()
        self.win.title("SHEILD – Dashboard")
        self.win.geometry("960x640")
        self.win.minsize(860, 580)
        self.win.configure(bg=C["bg"])

        self._build_layout()
        self._load_contacts()
        self._start_clock()
        self._update_location_label()

    # ── LAYOUT ──────────────────────────────────────
    def _build_layout(self):
        # Top bar
        topbar = tk.Frame(self.win, bg=C["panel"], height=56)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="🛡 SHEILD", font=("Georgia",18,"bold"),
                 fg=C["accent"], bg=C["panel"]).pack(side="left", padx=20)
        self.clock_lbl = tk.Label(topbar, text="", font=FONT_SMALL,
                                  fg=C["muted"], bg=C["panel"])
        self.clock_lbl.pack(side="right", padx=20)
        tk.Label(topbar, text=f"Welcome, {self.name}",
                 font=FONT_SUB, fg=C["text"], bg=C["panel"]).pack(side="right", padx=10)

        # Main body
        body = tk.Frame(self.win, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # Left panel
        left = tk.Frame(body, bg=C["panel"], width=260)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._build_left(left)

        # Right panel
        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True, padx=20, pady=16)
        self._build_right(right)

    # ── LEFT PANEL ───────────────────────────────────
    def _build_left(self, parent):
        # SOS button (pulsing)
        sos_frame = tk.Frame(parent, bg=C["panel"])
        sos_frame.pack(fill="x", padx=20, pady=(28,12))
        tk.Label(sos_frame, text="EMERGENCY", font=("Helvetica",9,"bold"),
                 fg=C["accent"], bg=C["panel"]).pack()

        self.sos_btn = tk.Button(
            sos_frame, text="SOS\nHOLD", font=FONT_SOS,
            bg=C["sos_bg"], fg="white",
            relief="flat", cursor="hand2",
            width=8, height=3,
            activebackground="#CC0000",
            command=self._sos_click
        )
        self.sos_btn.pack(pady=8)
        tk.Label(sos_frame, text="Tap to send emergency alert",
                 font=FONT_SMALL, fg=C["muted"], bg=C["panel"]).pack()

        self._pulse_sos()

        divider(parent)

        # Location
        tk.Label(parent, text="📍 CURRENT LOCATION",
                 font=("Helvetica",8,"bold"), fg=C["muted"], bg=C["panel"]).pack(anchor="w", padx=20)
        self.loc_lbl = tk.Label(parent, text="Detecting…",
                                font=FONT_SMALL, fg=C["safe"], bg=C["panel"],
                                wraplength=220, justify="left")
        self.loc_lbl.pack(anchor="w", padx=20, pady=(4,12))
        styled_button(parent, "🔄 Refresh Location",
                      self._update_location_label,
                      bg=C["border"], pady=4, padx=10).pack(padx=20, anchor="w")

        divider(parent)

        # SOS Log count
        tk.Label(parent, text="📋 SOS HISTORY",
                 font=("Helvetica",8,"bold"), fg=C["muted"], bg=C["panel"]).pack(anchor="w", padx=20)
        self.log_lbl = tk.Label(parent, text="",
                                font=FONT_SMALL, fg=C["text"], bg=C["panel"])
        self.log_lbl.pack(anchor="w", padx=20, pady=(4,0))
        self._refresh_log_count()

    # ── RIGHT PANEL ──────────────────────────────────
    def _build_right(self, parent):
        # Row 1: Emergency numbers
        tk.Label(parent, text="EMERGENCY HELPLINES",
                 font=("Helvetica",9,"bold"), fg=C["muted"], bg=C["bg"]).pack(anchor="w")

        helpline_row = tk.Frame(parent, bg=C["bg"])
        helpline_row.pack(fill="x", pady=(6,16))

        helplines = [
            ("🚔  Police", "100", C["accent"]),
            ("👩  Women Helpline", "1091", "#9B59B6"),
            ("🚑  Ambulance", "102", C["safe"]),
            ("🔥  Fire Brigade", "101", C["warn"]),
            ("☎  Emergency", "112", "#E74C3C"),
            ("👮  Nirbhaya Squad", "1800-180-7777", "#FF6B9D"),
        ]
        for name, num, color in helplines:
            self._helpline_card(helpline_row, name, num, color)

        divider(parent, pady=6)

        # Row 2: Trusted contacts + SOS log
        bottom = tk.Frame(parent, bg=C["bg"])
        bottom.pack(fill="both", expand=True)

        contacts_frame = tk.Frame(bottom, bg=C["bg"])
        contacts_frame.pack(side="left", fill="both", expand=True, padx=(0,10))
        self._build_contacts_panel(contacts_frame)

        log_frame = tk.Frame(bottom, bg=C["bg"])
        log_frame.pack(side="left", fill="both", expand=True)
        self._build_log_panel(log_frame)

    # ── HELPLINE CARD ────────────────────────────────
    def _helpline_card(self, parent, label, number, color):
        card = tk.Frame(parent, bg=C["surface"], cursor="hand2",
                        highlightthickness=1, highlightbackground=color)
        card.pack(side="left", padx=5, pady=4, ipadx=10, ipady=8)

        def _hover_in(e):  card.config(bg=color)
        def _hover_out(e): card.config(bg=C["surface"])
        card.bind("<Enter>", _hover_in)
        card.bind("<Leave>", _hover_out)

        tk.Label(card, text=label, font=("Helvetica",9,"bold"),
                 fg=C["text"], bg=C["surface"]).pack()
        tk.Label(card, text=number, font=("Courier",11,"bold"),
                 fg=color, bg=C["surface"]).pack()

        def _call(e=None):
            if messagebox.askyesno("Calling", f"Call {number}?", parent=self.win):
                make_call(number)

        card.bind("<Button-1>", _call)
        for child in card.winfo_children():
            child.bind("<Button-1>", _call)
            child.bind("<Enter>", _hover_in)
            child.bind("<Leave>", _hover_out)

    # ── TRUSTED CONTACTS PANEL ───────────────────────
    def _build_contacts_panel(self, parent):
        header = tk.Frame(parent, bg=C["bg"])
        header.pack(fill="x")
        tk.Label(header, text="TRUSTED CONTACTS",
                 font=("Helvetica",9,"bold"), fg=C["muted"], bg=C["bg"]).pack(side="left")
        styled_button(header, "+ Add", self._add_contact_popup,
                      bg=C["accent"], pady=2, padx=8,
                      font=("Helvetica",9,"bold")).pack(side="right")

        self.contacts_canvas = tk.Frame(parent, bg=C["surface"],
                                        highlightthickness=1,
                                        highlightbackground=C["border"])
        self.contacts_canvas.pack(fill="both", expand=True, pady=(8,0))

        self.contacts_inner = tk.Frame(self.contacts_canvas, bg=C["surface"])
        self.contacts_inner.pack(fill="both", expand=True, padx=8, pady=8)

    def _load_contacts(self):
        # Destroy and recreate inner frame to avoid stale widget issues
        self.contacts_inner.destroy()
        self.contacts_inner = tk.Frame(self.contacts_canvas, bg=C["surface"])
        self.contacts_inner.pack(fill="both", expand=True, padx=8, pady=8)

        rows = db_query(
            "SELECT id, contact_name, contact_phone, contact_email, relation "
            "FROM emergency_contacts WHERE user_phone=?",
            (self.phone,), fetch="all"
        )
        if not rows:
            tk.Label(self.contacts_inner,
                     text="No trusted contacts yet.\nClick '+ Add' to add one.",
                     font=FONT_SMALL, fg=C["muted"], bg=C["surface"],
                     justify="center").pack(pady=20)
            return
        for cid, cname, cphone, cemail, relation in rows:
            row = tk.Frame(self.contacts_inner, bg=C["panel"],
                           highlightthickness=1, highlightbackground=C["border"])
            row.pack(fill="x", pady=3, ipady=4)

            # Left side: name + relation
            left_f = tk.Frame(row, bg=C["panel"])
            left_f.pack(side="left", padx=8)
            tk.Label(left_f, text=f"👤 {cname}", font=("Helvetica",10,"bold"),
                     fg=C["text"], bg=C["panel"]).pack(anchor="w")
            tk.Label(left_f, text=relation or "Contact", font=FONT_SMALL,
                     fg=C["muted"], bg=C["panel"]).pack(anchor="w")

            # Right side: email + delete
            right_f = tk.Frame(row, bg=C["panel"])
            right_f.pack(side="right", padx=8)
            tk.Label(right_f, text=cemail or "", font=FONT_SMALL,
                     fg=C["safe"], bg=C["panel"]).pack(anchor="e")

            def _del(cid=cid):
                if messagebox.askyesno("Remove Contact",
                                       "Remove this contact?", parent=self.win):
                    db_query("DELETE FROM emergency_contacts WHERE id=?", (cid,))
                    self._load_contacts()

            tk.Button(right_f, text="✕ Remove", font=("Helvetica",8), fg=C["accent"],
                      bg=C["panel"], relief="flat", cursor="hand2",
                      activebackground=C["border"], activeforeground=C["accent"],
                      command=_del).pack(anchor="e", pady=2)

    # ── SOS LOG PANEL ────────────────────────────────
    def _build_log_panel(self, parent):
        tk.Label(parent, text="RECENT SOS ALERTS",
                 font=("Helvetica",9,"bold"), fg=C["muted"], bg=C["bg"]).pack(anchor="w")
        self.log_frame = tk.Frame(parent, bg=C["surface"],
                                  highlightthickness=1,
                                  highlightbackground=C["border"])
        self.log_frame.pack(fill="both", expand=True, pady=(8,0))
        self._refresh_sos_log()

    def _refresh_sos_log(self):
        for w in self.log_frame.winfo_children():
            w.destroy()
        rows = db_query(
            "SELECT location, timestamp FROM sos_logs WHERE user_phone=? ORDER BY id DESC LIMIT 6",
            (self.phone,), fetch="all"
        )
        if not rows:
            tk.Label(self.log_frame, text="No SOS alerts sent yet.",
                     font=FONT_SMALL, fg=C["muted"], bg=C["surface"]).pack(pady=20)
            return
        for loc, ts in rows:
            row = tk.Frame(self.log_frame, bg=C["surface"])
            row.pack(fill="x", padx=8, pady=2)
            tk.Label(row, text="🚨", font=("Helvetica",10),
                     bg=C["surface"]).pack(side="left")
            info = tk.Frame(row, bg=C["surface"])
            info.pack(side="left", padx=4)
            tk.Label(info, text=loc or "Unknown", font=FONT_SMALL,
                     fg=C["text"], bg=C["surface"]).pack(anchor="w")
            tk.Label(info, text=ts[:19] if ts else "", font=("Helvetica",8),
                     fg=C["muted"], bg=C["surface"]).pack(anchor="w")

    def _refresh_log_count(self):
        row = db_query("SELECT COUNT(*) FROM sos_logs WHERE user_phone=?",
                       (self.phone,), fetch="one")
        count = row[0] if row else 0
        self.log_lbl.config(text=f"{count} alerts sent total")

    # ── CLOCK ────────────────────────────────────────
    def _start_clock(self):
        def _tick():
            now = datetime.now().strftime("%d %b %Y  |  %H:%M:%S")
            self.clock_lbl.config(text=now)
            self.win.after(1000, _tick)
        _tick()

    # ── LOCATION ─────────────────────────────────────
    def _update_location_label(self):
        self.loc_lbl.config(text="Detecting…", fg=C["warn"])
        def _fetch():
            loc = get_live_location()
            self.loc_lbl.config(text=loc.get("display","Unknown"), fg=C["safe"])
        threading.Thread(target=_fetch, daemon=True).start()

    # ── SOS ──────────────────────────────────────────
    def _pulse_sos(self):
        colors = [C["sos_bg"], "#CC0030"]
        self._sos_color_idx = getattr(self, "_sos_color_idx", 0)
        self.sos_btn.config(bg=colors[self._sos_color_idx % 2])
        self._sos_color_idx += 1
        self.win.after(700, self._pulse_sos)

    def _sos_click(self):
        confirm = messagebox.askyesno(
            "🚨 SOS ALERT",
            "This will send an EMERGENCY ALERT (Email + WhatsApp) with your LIVE LOCATION "
            "to ALL your trusted contacts.\n\nContinue?",
            parent=self.win
        )
        if not confirm:
            return
        self.sos_btn.config(text="SENDING…", state="disabled")

        def _on_done(sent_count, wa_count, location):
            self.sos_btn.config(text="SOS\nHOLD", state="normal")
            self._refresh_sos_log()
            self._refresh_log_count()
            if sent_count or wa_count:
                parts = []
                if sent_count:
                    parts.append(f"📧 Email sent to {sent_count} contact(s)")
                if wa_count:
                    parts.append(f"💬 WhatsApp sent to {wa_count} contact(s)")
                messagebox.showinfo(
                    "SOS Sent ✅",
                    "\n".join(parts) + f"\nLocation: {location}",
                    parent=self.win
                )
            else:
                messagebox.showwarning(
                    "SOS Logged",
                    "Alert logged but delivery failed.\n"
                    "Check SENDER_EMAIL / SENDER_PASSWORD config\n"
                    "and ensure contact phone numbers include country code.",
                    parent=self.win
                )

        trigger_sos(self.phone, self.name, status_callback=_on_done)

    # ── ADD CONTACT ──────────────────────────────────
    def _add_contact_popup(self):
        popup = tk.Toplevel(self.win)
        popup.title("Add Trusted Contact")
        popup.geometry("420x520")
        popup.configure(bg=C["bg"])
        popup.resizable(False, False)
        popup.grab_set()   # Make popup modal - must close before using dashboard
        popup.focus_set()

        # Header
        tk.Label(popup, text="👤  Add Trusted Contact", font=FONT_HEAD,
                 fg=C["accent"], bg=C["bg"]).pack(pady=(20, 4))
        tk.Label(popup, text="Fill in the details below and click Save",
                 font=FONT_SMALL, fg=C["muted"], bg=C["bg"]).pack(pady=(0, 14))

        # Card
        card = tk.Frame(popup, bg=C["surface"],
                        highlightthickness=1, highlightbackground=C["border"])
        card.pack(fill="x", padx=24, pady=(0, 16))

        entries = {}
        fields = [
            ("Full Name *",          "name",  ""),
            ("Phone Number",         "phone", ""),
            ("Email Address *",      "email", ""),
            ("Relation (e.g. Sister)", "rel", ""),
        ]
        for label, key, show in fields:
            f = tk.Frame(card, bg=C["surface"])
            f.pack(fill="x", padx=16, pady=(12, 0))
            tk.Label(f, text=label, font=FONT_SMALL,
                     fg=C["muted"], bg=C["surface"]).pack(anchor="w")
            e = tk.Entry(f, show=show, width=36,
                         font=FONT_BODY, bg=C["border"], fg=C["text"],
                         insertbackground=C["accent"], relief="flat",
                         highlightthickness=1, highlightcolor=C["accent"],
                         highlightbackground=C["border"])
            e.pack(fill="x", pady=(4, 0), ipady=8)
            entries[key] = e

        # Buttons row
        btn_row = tk.Frame(card, bg=C["surface"])
        btn_row.pack(fill="x", padx=16, pady=16)

        def save():
            name  = entries["name"].get().strip()
            phone = entries["phone"].get().strip()
            email = entries["email"].get().strip()
            rel   = entries["rel"].get().strip() or "Contact"

            if not name:
                messagebox.showerror("Missing", "Full Name is required.", parent=popup)
                entries["name"].focus_set()
                return
            if not email:
                messagebox.showerror("Missing", "Email Address is required.", parent=popup)
                entries["email"].focus_set()
                return

            db_query(
                "INSERT INTO emergency_contacts "
                "(user_phone, contact_name, contact_phone, contact_email, relation) "
                "VALUES (?, ?, ?, ?, ?)",
                (self.phone, name, phone, email, rel)
            )
            self._load_contacts()
            popup.destroy()
            messagebox.showinfo("Contact Added ✅",
                                f"'{name}' has been added to your trusted contacts.",
                                parent=self.win)

        tk.Button(btn_row, text="💾  Save Contact",
                  font=FONT_LABEL, bg=C["accent"], fg="white",
                  relief="flat", cursor="hand2", padx=16, pady=9,
                  activebackground=C["accent2"], activeforeground="white",
                  command=save).pack(side="left")

        tk.Button(btn_row, text="Cancel",
                  font=FONT_LABEL, bg=C["border"], fg=C["muted"],
                  relief="flat", cursor="hand2", padx=16, pady=9,
                  activebackground=C["panel"],
                  command=popup.destroy).pack(side="left", padx=(10, 0))

        entries["name"].focus_set()

# ══════════════════════════════════════════════════════
#  LOGIN SCREEN
# ══════════════════════════════════════════════════════
class LoginSystem:
    def __init__(self, root):
        self.root = root
        root.title("SHEILD – Women Safety App")
        root.geometry("860x580")
        root.configure(bg=C["bg"])
        root.resizable(False, False)
        self._build()

    def _build(self):
        # Left decorative panel
        left = tk.Frame(self.root, bg=C["panel"], width=380)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Label(left, text="🛡", font=("Arial",64), bg=C["panel"],
                 fg=C["accent"]).pack(pady=(80,0))
        tk.Label(left, text="SHEILD", font=("Georgia",32,"bold"),
                 fg=C["accent"], bg=C["panel"]).pack()
        tk.Label(left, text="Women Safety App",
                 font=("Helvetica",13), fg=C["muted"], bg=C["panel"]).pack(pady=(4,32))

        for txt, col in [("🔒  Secure Login", C["safe"]),
                         ("📍  Live Location SOS", C["accent"]),
                         ("📧  Auto Alert Emails", C["accent2"]),
                         ("💬  WhatsApp SOS Alerts", C["safe"]),
                         ("📞  Emergency Helplines", C["warn"])]:
            tk.Label(left, text=txt, font=("Helvetica",11), fg=col,
                     bg=C["panel"]).pack(anchor="w", padx=48, pady=4)

        # Right login form
        right = tk.Frame(self.root, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)

        form = tk.Frame(right, bg=C["bg"])
        form.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(form, text="Sign In", font=("Georgia",24,"bold"),
                 fg=C["text"], bg=C["bg"]).pack(pady=(0,4))
        tk.Label(form, text="Stay safe. We're with you.",
                 font=FONT_SUB, fg=C["muted"], bg=C["bg"]).pack(pady=(0,28))

        card = card_frame(form)
        card.pack(ipadx=20, ipady=10)

        for label, key, show in [("Phone Number","phone",""), ("Password","pwd","*")]:
            f = tk.Frame(card, bg=C["surface"])
            f.pack(fill="x", padx=24, pady=(14,0))
            tk.Label(f, text=label, font=FONT_SMALL,
                     fg=C["muted"], bg=C["surface"]).pack(anchor="w")
            e = styled_entry(f, show=show, width=32)
            e.pack(fill="x", pady=(4,0), ipady=9)
            setattr(self, f"{key}_entry", e)

        styled_button(card, "SIGN IN →", self.login, width=30, pady=12).pack(pady=(20,8))
        tk.Button(card, text="Don't have an account? Register here",
                  font=("Helvetica",9), fg=C["accent2"], bg=C["surface"],
                  relief="flat", cursor="hand2", activeforeground=C["accent"],
                  activebackground=C["surface"], command=self.show_register).pack(pady=(0,12))

    def show_register(self):
        RegisterWindow(self.root)

    def login(self):
        phone = self.phone_entry.get().strip()
        pwd   = self.pwd_entry.get()
        if not phone or not pwd:
            messagebox.showerror("Login Failed", "Please enter all fields.", parent=self.root)
            return
        user = db_query(
            "SELECT name, hashed_password, salt FROM users WHERE phone=?",
            (phone,), fetch="one"
        )
        if user and verify_password(user[1], user[2], pwd):
            Dashboard(phone, user[0])
        else:
            messagebox.showerror("Login Failed",
                                 "Invalid phone number or password.", parent=self.root)

# ══════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    setup_database()
    root = tk.Tk()
    app  = LoginSystem(root)
    root.mainloop()
