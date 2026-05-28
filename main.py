from __future__ import annotations

from email import policy
from email.parser import BytesParser
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from auth.login import login_user
from auth.otp import EmailOTPChallenge, OTPDeliveryError, start_email_otp, verify_email_otp
from auth.register import register_user
from database.database import (
    LOG_DIR,
    REPORT_DIR,
    build_session,
    health_check,
    list_recent_scans,
    list_security_events,
    log_event,
    save_scan,
    session_expired,
)
from detection.risk_score import AnalysisResult, calculate_risk

APP_NAME = "PhishGuard"
APP_VERSION = "2.0.0"
MAX_EMAIL_LENGTH = 50000
SUPPORTED_EMAIL_FILES = {".txt", ".eml"}
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.@+-]{3,64}")
USERNAME_HELP = "Use 3-64 characters: letters, numbers, ., _, @, +, or -"

LIGHT_THEME = {
    "bg": "#eef3f8",
    "surface": "#ffffff",
    "surface_alt": "#f8fafc",
    "text": "#102033",
    "muted": "#627386",
    "border": "#d8e2ec",
    "primary": "#0f766e",
    "primary_dark": "#115e59",
    "secondary": "#2563eb",
    "field": "#fbfdff",
    "table": "#ffffff",
}

DARK_THEME = {
    "bg": "#111827",
    "surface": "#1f2937",
    "surface_alt": "#273244",
    "text": "#f8fafc",
    "muted": "#cbd5e1",
    "border": "#3b4758",
    "primary": "#2dd4bf",
    "primary_dark": "#14b8a6",
    "secondary": "#60a5fa",
    "field": "#0f172a",
    "table": "#172033",
}

SAMPLE_PHISH = """From: security-team@paypa1-security-alerts.com
Reply-To: accounts@bit.ly
Subject: Urgent: Verify your account immediately

Dear Customer,

Your account has been suspended due to unusual activity. Verify your account immediately within 24 hours to avoid permanent closure.
Click here: http://bit.ly/verify-paypal-login
You must login immediately and confirm identity.

Regards,
Security Team
"""

SAMPLE_LEGIT = """From: support@microsoft.com
Reply-To: support@microsoft.com
Subject: Your monthly subscription receipt

Hello,

Thank you for your payment. Your receipt and subscription details are available in your account dashboard.
Visit https://account.microsoft.com securely to view details.

Best regards,
Microsoft Billing
"""


class PhishGuardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1220x780")
        self.minsize(1080, 700)
        self.configure(bg="#f4f7fb")

        health_check()
        self._configure_logging()

        self.pending_user: dict | None = None
        self.pending_otp: EmailOTPChallenge | None = None
        self.session: dict | None = None
        self.last_result: AnalysisResult | None = None
        self.last_email_text: str = ""
        self.analysis_mode = tk.StringVar(value="hybrid")
        self.dark_mode = tk.BooleanVar(value=False)
        self.colors = LIGHT_THEME
        self.theme_widgets: list[tk.Widget] = []

        self.style = ttk.Style(self)
        self._setup_styles()
        self._build_shell()
        self._show_frame(self.login_frame)
        self.after(5000, self._session_guard)

    def _configure_logging(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("phishguard")
        logger.setLevel(logging.INFO)
        if logger.handlers:
            return
        handler = RotatingFileHandler(LOG_DIR / "app.log", maxBytes=500_000, backupCount=3)
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)

    def _setup_styles(self) -> None:
        c = self.colors
        self.style.theme_use("clam")
        self.style.configure(".", font=("Avenir Next", 10))
        self.style.configure("TFrame", background=c["bg"])
        self.style.configure("Card.TFrame", background=c["surface"], relief="flat")
        self.style.configure("HeaderBar.TFrame", background=c["surface"])
        self.style.configure("Toolbar.TFrame", background=c["surface"])
        self.style.configure("Metric.TFrame", background=c["surface_alt"])
        self.style.configure("AppTitle.TLabel", font=("Avenir Next", 22, "bold"), foreground=c["text"], background=c["surface"])
        self.style.configure("Header.TLabel", font=("Avenir Next", 26, "bold"), foreground=c["text"], background=c["bg"])
        self.style.configure("HeroTitle.TLabel", font=("Avenir Next", 28, "bold"), foreground=c["text"], background=c["surface"])
        self.style.configure("Subheader.TLabel", font=("Avenir Next", 12), foreground=c["muted"], background=c["surface"])
        self.style.configure("Muted.TLabel", font=("Avenir Next", 11), foreground=c["muted"], background=c["bg"])
        self.style.configure("CardMuted.TLabel", font=("Avenir Next", 10), foreground=c["muted"], background=c["surface"])
        self.style.configure("CardTitle.TLabel", font=("Avenir Next", 14, "bold"), foreground=c["text"], background=c["surface"])
        self.style.configure("SectionTitle.TLabel", font=("Avenir Next", 11, "bold"), foreground=c["text"], background=c["surface"])
        self.style.configure("Badge.TLabel", font=("Avenir Next", 10, "bold"), foreground=c["primary_dark"], background=c["surface_alt"], padding=(10, 5))
        self.style.configure("MetricValue.TLabel", font=("Avenir Next", 18, "bold"), foreground=c["text"], background=c["surface_alt"])
        self.style.configure("MetricLabel.TLabel", font=("Avenir Next", 9), foreground=c["muted"], background=c["surface_alt"])
        self.style.configure("Score.TLabel", font=("Avenir Next", 42, "bold"), background=c["surface"], foreground=c["secondary"])
        self.style.configure("Risk.TLabel", font=("Avenir Next", 16, "bold"), background=c["surface"], foreground=c["secondary"])
        self.style.configure("Primary.TButton", font=("Avenir Next", 11, "bold"), padding=(14, 9), foreground="#ffffff", background=c["primary"])
        self.style.map("Primary.TButton", background=[("active", c["primary_dark"]), ("disabled", c["border"])])
        self.style.configure("Secondary.TButton", font=("Avenir Next", 10), padding=(10, 8), foreground=c["text"], background=c["surface_alt"])
        self.style.map("Secondary.TButton", background=[("active", c["border"]), ("disabled", c["surface_alt"])])
        self.style.configure("TNotebook", background=c["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(16, 9), font=("Avenir Next", 10, "bold"), background=c["surface_alt"], foreground=c["muted"])
        self.style.map("TNotebook.Tab", background=[("selected", c["surface"])], foreground=[("selected", c["text"])])
        self.style.configure("TRadiobutton", background=c["surface"], foreground=c["text"])
        self.style.configure("TCheckbutton", background=c["surface"], foreground=c["text"])
        self.style.configure("Horizontal.TProgressbar", troughcolor=c["surface_alt"], background=c["primary"], bordercolor=c["surface"])
        self.style.configure("Treeview", rowheight=30, font=("Avenir Next", 10), background=c["table"], fieldbackground=c["table"], foreground=c["text"], borderwidth=0)
        self.style.configure("Treeview.Heading", font=("Avenir Next", 10, "bold"), background=c["surface_alt"], foreground=c["text"])

    def _build_shell(self) -> None:
        self.root_frame = ttk.Frame(self)
        self.root_frame.pack(fill="both", expand=True)

        self.login_frame = ttk.Frame(self.root_frame, style="TFrame")
        self.signup_frame = ttk.Frame(self.root_frame, style="TFrame")
        self.otp_frame = ttk.Frame(self.root_frame, style="TFrame")
        self.dashboard_frame = ttk.Frame(self.root_frame, style="TFrame")
        for frame in (self.login_frame, self.signup_frame, self.otp_frame, self.dashboard_frame):
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._build_login()
        self._build_signup()
        self._build_otp()
        self._build_dashboard()

    def _show_frame(self, frame: ttk.Frame) -> None:
        frame.tkraise()

    def _build_login(self) -> None:
        card = ttk.Frame(self.login_frame, style="Card.TFrame", padding=34)
        card.place(relx=0.5, rely=0.5, anchor="center", width=640, height=570)

        ttk.Label(card, text="PhishGuard", style="HeroTitle.TLabel").pack(anchor="center", pady=(4, 0))
        ttk.Label(card, text="Email threat triage and phishing awareness", style="CardMuted.TLabel").pack(anchor="center", pady=(0, 22))
        ttk.Label(card, text="Secure Workspace Login", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text="Sign in to scan suspicious email content, review risk indicators, and export investigation reports.",
            style="CardMuted.TLabel",
            wraplength=540,
        ).pack(anchor="w", pady=(4, 0))

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x", pady=16)
        ttk.Label(form, text="Username or Email", style="CardMuted.TLabel").pack(anchor="w")
        self.username_entry = ttk.Entry(form, font=("Avenir Next", 12))
        self.username_entry.pack(fill="x", pady=(2, 14), ipady=6)

        ttk.Label(form, text="Password", style="CardMuted.TLabel").pack(anchor="w")
        self.password_entry = ttk.Entry(form, show="*", font=("Avenir Next", 12))
        self.password_entry.pack(fill="x", pady=(2, 20), ipady=6)

        row = ttk.Frame(form, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Sign In", style="Primary.TButton", command=self._handle_login).pack(side="left")
        ttk.Button(row, text="Clear", style="Secondary.TButton", command=self._clear_login).pack(side="left", padx=8)
        ttk.Button(row, text="Create Account", style="Secondary.TButton", command=lambda: self._show_frame(self.signup_frame)).pack(side="left")

        note = (
            "Use your email address to sign in.\n"
            "PhishGuard sends the verification code to that same email."
        )
        ttk.Label(card, text=note, style="CardMuted.TLabel", justify="left").pack(anchor="w", pady=(26, 0))

    def _build_signup(self) -> None:
        card = ttk.Frame(self.signup_frame, style="Card.TFrame", padding=34)
        card.place(relx=0.5, rely=0.5, anchor="center", width=640, height=620)

        ttk.Label(card, text="Create PhishGuard Account", style="HeroTitle.TLabel").pack(anchor="center", pady=(4, 0))
        ttk.Label(card, text="New accounts are stored securely as standard users.", style="CardMuted.TLabel").pack(anchor="center", pady=(0, 22))
        ttk.Label(card, text="Sign Up", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text="Choose a username and password. The password is stored as a bcrypt hash in the SQLite database.",
            style="CardMuted.TLabel",
            wraplength=540,
        ).pack(anchor="w", pady=(4, 0))

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x", pady=16)
        ttk.Label(form, text="Username or Email", style="CardMuted.TLabel").pack(anchor="w")
        self.signup_username_entry = ttk.Entry(form, font=("Avenir Next", 12))
        self.signup_username_entry.pack(fill="x", pady=(2, 14), ipady=6)

        ttk.Label(form, text="Password", style="CardMuted.TLabel").pack(anchor="w")
        self.signup_password_entry = ttk.Entry(form, show="*", font=("Avenir Next", 12))
        self.signup_password_entry.pack(fill="x", pady=(2, 14), ipady=6)

        ttk.Label(form, text="Confirm Password", style="CardMuted.TLabel").pack(anchor="w")
        self.signup_confirm_entry = ttk.Entry(form, show="*", font=("Avenir Next", 12))
        self.signup_confirm_entry.pack(fill="x", pady=(2, 18), ipady=6)

        row = ttk.Frame(form, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Create Account", style="Primary.TButton", command=self._handle_signup).pack(side="left")
        ttk.Button(row, text="Back to Login", style="Secondary.TButton", command=lambda: self._show_frame(self.login_frame)).pack(side="left", padx=8)
        ttk.Button(row, text="Clear", style="Secondary.TButton", command=self._clear_signup).pack(side="left")

        note = (
            "After signup, sign in with the same username and password.\n"
            "Use an email address so PhishGuard can send your login OTP."
        )
        ttk.Label(card, text=note, style="CardMuted.TLabel", justify="left").pack(anchor="w", pady=(26, 0))

    def _build_otp(self) -> None:
        card = ttk.Frame(self.otp_frame, style="Card.TFrame", padding=34)
        card.place(relx=0.5, rely=0.5, anchor="center", width=640, height=460)

        ttk.Label(card, text="Check Your Email", style="HeroTitle.TLabel").pack(anchor="center", pady=(4, 0))
        self.otp_info_label = ttk.Label(
            card,
            text="Enter the 6-digit code sent to your email.",
            style="CardMuted.TLabel",
            justify="center",
            wraplength=520,
        )
        self.otp_info_label.pack(anchor="center", pady=(0, 22))
        ttk.Label(card, text="Verification Code", style="CardTitle.TLabel").pack(anchor="w")
        self.otp_entry = ttk.Entry(card, font=("Avenir Next", 22), justify="center")
        self.otp_entry.pack(fill="x", pady=(8, 18), ipady=8)

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Verify", style="Primary.TButton", command=self._handle_otp).pack(side="left")
        ttk.Button(row, text="Resend Code", style="Secondary.TButton", command=self._resend_otp).pack(side="left", padx=8)
        ttk.Button(row, text="Back to Login", style="Secondary.TButton", command=self._cancel_otp).pack(side="left")

        ttk.Label(
            card,
            text="The code expires in 5 minutes. It is sent to the same email address you used to sign in.",
            style="CardMuted.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(28, 0))

    def _build_dashboard(self) -> None:
        header = ttk.Frame(self.dashboard_frame, style="HeaderBar.TFrame", padding=(22, 16))
        header.pack(fill="x")
        brand = ttk.Frame(header, style="HeaderBar.TFrame")
        brand.pack(side="left", fill="x", expand=True)
        ttk.Label(brand, text="PhishGuard", style="AppTitle.TLabel").pack(anchor="w")
        ttk.Label(brand, text="Email threat triage workspace", style="Subheader.TLabel").pack(anchor="w")
        ttk.Button(header, text="Logout", style="Secondary.TButton", command=self._logout).pack(side="right")
        ttk.Checkbutton(header, text="Dark mode", variable=self.dark_mode, command=self._toggle_theme).pack(side="right", padx=(0, 12))
        self.user_badge = ttk.Label(header, text="", style="Badge.TLabel")
        self.user_badge.pack(side="right", padx=(0, 12))

        workspace_strip = ttk.Frame(self.dashboard_frame, style="Card.TFrame", padding=(18, 12))
        workspace_strip.pack(fill="x", padx=20, pady=(14, 10))
        ttk.Label(workspace_strip, text="Email Threat Scanner", style="CardTitle.TLabel").pack(side="left")
        ttk.Label(
            workspace_strip,
            text="Analyze suspicious messages, understand why they are risky, and export evidence reports.",
            style="CardMuted.TLabel",
        ).pack(side="left", padx=(16, 0))
        self.workspace_badge = ttk.Label(workspace_strip, text="Personal workspace", style="Badge.TLabel")
        self.workspace_badge.pack(side="right")

        self.notebook = ttk.Notebook(self.dashboard_frame)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.analysis_tab = ttk.Frame(self.notebook, style="TFrame")
        self.history_tab = ttk.Frame(self.notebook, style="TFrame")
        self.admin_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.analysis_tab, text="Email Analysis")
        self.notebook.add(self.history_tab, text="Scan History")
        self._build_analysis_tab()
        self._build_history_tab()
        self._build_admin_tab()

    def _build_analysis_tab(self) -> None:
        self.analysis_tab.columnconfigure(0, weight=3, uniform="analysis")
        self.analysis_tab.columnconfigure(1, weight=2, uniform="analysis")
        self.analysis_tab.rowconfigure(0, weight=1)

        left = ttk.Frame(self.analysis_tab, style="Card.TFrame", padding=18)
        left.grid(row=0, column=0, sticky="nsew", padx=(14, 8), pady=14)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)
        ttk.Label(left, text="Email / Header Input", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(left, text="Paste an email, load a .txt/.eml file, or use a demo sample.", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 8))

        source_row = ttk.Frame(left, style="Card.TFrame")
        source_row.pack(fill="x", pady=(0, 8))
        self.input_meta_label = ttk.Label(source_row, text="Manual input | 0 characters", style="Badge.TLabel")
        self.input_meta_label.pack(side="left")
        ttk.Label(source_row, text=f"Max {MAX_EMAIL_LENGTH:,} characters", style="CardMuted.TLabel").pack(side="right")

        self.email_text = ScrolledText(
            left,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["field"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            height=22,
            padx=12,
            pady=12,
        )
        self.email_text.pack(fill="both", expand=True)
        self.email_text.bind("<KeyRelease>", lambda _event: self._update_input_meta("Manual input"))
        self.theme_widgets.append(self.email_text)

        row = ttk.Frame(left, style="Card.TFrame")
        row.pack(fill="x", pady=(10, 0))
        ttk.Button(row, text="Analyze Email", style="Primary.TButton", command=self._run_analysis).pack(side="left")
        ttk.Button(row, text="Open File", style="Secondary.TButton", command=self._load_email_file).pack(side="left", padx=6)
        ttk.Button(row, text="Phishing Sample", style="Secondary.TButton", command=lambda: self._set_email_text(SAMPLE_PHISH, "Phishing sample")).pack(side="left", padx=6)
        ttk.Button(row, text="Legit Sample", style="Secondary.TButton", command=lambda: self._set_email_text(SAMPLE_LEGIT, "Legitimate sample")).pack(side="left", padx=6)
        ttk.Button(row, text="Clear", style="Secondary.TButton", command=lambda: self._set_email_text("", "Manual input")).pack(side="left", padx=6)

        mode_row = ttk.Frame(left, style="Card.TFrame")
        mode_row.pack(fill="x", pady=(10, 0))
        ttk.Label(mode_row, text="Detection Mode:", style="Muted.TLabel").pack(side="left", padx=(0, 10))
        ttk.Radiobutton(mode_row, text="Hybrid", value="hybrid", variable=self.analysis_mode).pack(side="left")
        ttk.Radiobutton(mode_row, text="Heuristic", value="heuristic", variable=self.analysis_mode).pack(side="left", padx=8)
        ttk.Radiobutton(mode_row, text="ML", value="ml", variable=self.analysis_mode).pack(side="left", padx=8)

        right = ttk.Frame(self.analysis_tab, style="Card.TFrame", padding=18)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 14), pady=14)
        ttk.Label(right, text="Risk Summary", style="CardTitle.TLabel").pack(anchor="w")
        meter_wrap = ttk.Frame(right, style="Card.TFrame")
        meter_wrap.pack(fill="x", pady=(6, 2))
        self.score_label = ttk.Label(meter_wrap, text="0", style="Score.TLabel", foreground="#2563eb")
        self.score_label.pack(side="left")
        self.risk_label = ttk.Label(meter_wrap, text="Low", style="Risk.TLabel", foreground="#2563eb")
        self.risk_label.pack(side="left", padx=10)
        self.risk_bar = ttk.Progressbar(right, orient="horizontal", mode="determinate", length=320)
        self.risk_bar.pack(fill="x", pady=(0, 12))

        metric_row = ttk.Frame(right, style="Card.TFrame")
        metric_row.pack(fill="x", pady=(0, 12))
        for index in range(3):
            metric_row.columnconfigure(index, weight=1)
        indicator_metric = ttk.Frame(metric_row, style="Metric.TFrame", padding=10)
        indicator_metric.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.indicator_count_label = ttk.Label(indicator_metric, text="0", style="MetricValue.TLabel")
        self.indicator_count_label.pack(anchor="w")
        ttk.Label(indicator_metric, text="Indicators", style="MetricLabel.TLabel").pack(anchor="w")
        url_metric = ttk.Frame(metric_row, style="Metric.TFrame", padding=10)
        url_metric.grid(row=0, column=1, sticky="ew", padx=6)
        self.url_count_label = ttk.Label(url_metric, text="0", style="MetricValue.TLabel")
        self.url_count_label.pack(anchor="w")
        ttk.Label(url_metric, text="URLs", style="MetricLabel.TLabel").pack(anchor="w")
        mode_metric = ttk.Frame(metric_row, style="Metric.TFrame", padding=10)
        mode_metric.grid(row=0, column=2, sticky="ew", padx=(6, 0))
        self.mode_result_label = ttk.Label(mode_metric, text="Hybrid", style="MetricValue.TLabel")
        self.mode_result_label.pack(anchor="w")
        ttk.Label(mode_metric, text="Mode", style="MetricLabel.TLabel").pack(anchor="w")

        self.risk_message_label = ttk.Label(
            right,
            text="Ready to analyze. Load or paste an email to begin.",
            style="CardMuted.TLabel",
            wraplength=430,
        )
        self.risk_message_label.pack(anchor="w", fill="x", pady=(0, 10))

        ttk.Label(right, text="Explanation", style="SectionTitle.TLabel").pack(anchor="w", pady=(0, 6))
        self.explain_box = ScrolledText(
            right,
            wrap="word",
            height=7,
            font=("Avenir Next", 10),
            bg=self.colors["field"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            padx=10,
            pady=8,
        )
        self.explain_box.pack(fill="x")
        self.explain_box.configure(state="disabled")
        self.theme_widgets.append(self.explain_box)

        ttk.Label(right, text="Indicators", style="SectionTitle.TLabel").pack(anchor="w", pady=(12, 6))
        self.indicator_table = ttk.Treeview(right, columns=("points", "evidence"), show="headings", height=8)
        self.indicator_table.heading("points", text="Points")
        self.indicator_table.heading("evidence", text="Evidence")
        self.indicator_table.column("points", width=70, anchor="center")
        self.indicator_table.column("evidence", width=300)
        self.indicator_table.pack(fill="both", expand=True)

        ttk.Label(right, text="Detected URLs", style="SectionTitle.TLabel").pack(anchor="w", pady=(10, 6))
        self.url_list = tk.Listbox(right, height=3, font=("Menlo", 10), relief="flat", bg=self.colors["field"], fg=self.colors["text"])
        self.url_list.pack(fill="x")
        self.theme_widgets.append(self.url_list)

        ttk.Label(right, text="Recommended Actions", style="SectionTitle.TLabel").pack(anchor="w", pady=(10, 6))
        self.action_list = tk.Listbox(right, height=3, font=("Avenir Next", 10), relief="flat", bg=self.colors["field"], fg=self.colors["text"])
        self.action_list.pack(fill="x")
        self.theme_widgets.append(self.action_list)

        export_row = ttk.Frame(right, style="Card.TFrame")
        export_row.pack(anchor="e", pady=(10, 0))
        self.export_json_btn = ttk.Button(export_row, text="Export JSON", style="Secondary.TButton", command=self._export_json)
        self.export_json_btn.pack(side="left", padx=4)
        self.export_pdf_btn = ttk.Button(export_row, text="Export PDF", style="Secondary.TButton", command=self._export_pdf)
        self.export_pdf_btn.pack(side="left", padx=4)
        self.export_json_btn.configure(state="disabled")
        self.export_pdf_btn.configure(state="disabled")

    def _build_history_tab(self) -> None:
        card = ttk.Frame(self.history_tab, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True, padx=10, pady=10)
        header = ttk.Frame(card, style="Card.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Recent Scan Activity", style="CardTitle.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh", style="Secondary.TButton", command=self._refresh_history).pack(side="right")
        self.history_caption = ttk.Label(card, text="Your previous scans are stored locally for review and reporting.", style="CardMuted.TLabel")
        self.history_caption.pack(anchor="w", pady=(6, 0))

        self.history_table = ttk.Treeview(card, columns=("user", "score", "risk", "mode", "count", "time"), show="headings")
        for col, text, width in [
            ("user", "User", 110),
            ("score", "Score", 80),
            ("risk", "Risk", 90),
            ("mode", "Mode", 90),
            ("count", "Indicators", 100),
            ("time", "Time (UTC)", 360),
        ]:
            self.history_table.heading(col, text=text)
            self.history_table.column(col, width=width, anchor="center")
        self.history_table.pack(fill="both", expand=True, pady=(10, 0))

    def _build_admin_tab(self) -> None:
        card = ttk.Frame(self.admin_tab, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True, padx=10, pady=10)
        header = ttk.Frame(card, style="Card.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Admin Security Events", style="CardTitle.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh", style="Secondary.TButton", command=self._refresh_admin_events).pack(side="right")
        ttk.Label(
            card,
            text="Monitor authentication, OTP delivery, scan validation, report export, and session activity.",
            style="CardMuted.TLabel",
        ).pack(anchor="w", pady=(6, 0))

        table_wrap = ttk.Frame(card, style="Card.TFrame")
        table_wrap.pack(fill="both", expand=True, pady=(10, 0))
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)

        self.admin_events_table = ttk.Treeview(
            table_wrap,
            columns=("time", "user", "event", "status", "details"),
            show="headings",
        )
        for col, text, width, anchor in [
            ("time", "Time (UTC)", 220, "center"),
            ("user", "User", 180, "center"),
            ("event", "Event", 150, "center"),
            ("status", "Status", 90, "center"),
            ("details", "Details", 520, "w"),
        ]:
            self.admin_events_table.heading(col, text=text)
            self.admin_events_table.column(col, width=width, anchor=anchor)
        self.admin_events_table.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=self.admin_events_table.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.admin_events_table.configure(yscrollcommand=scrollbar.set)

    def _clear_login(self) -> None:
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")

    def _clear_signup(self) -> None:
        self.signup_username_entry.delete(0, "end")
        self.signup_password_entry.delete(0, "end")
        self.signup_confirm_entry.delete(0, "end")

    def _handle_signup(self) -> None:
        username = self.signup_username_entry.get().strip()
        password = self.signup_password_entry.get().strip()
        confirm = self.signup_confirm_entry.get().strip()

        if not USERNAME_PATTERN.fullmatch(username):
            messagebox.showerror("Invalid Username", USERNAME_HELP)
            return
        if len(password) < 8:
            messagebox.showerror("Invalid Password", "Password must be at least 8 characters.")
            return
        if password != confirm:
            messagebox.showerror("Password Mismatch", "Password and confirm password must match.")
            return
        if "@" not in username:
            messagebox.showerror("Email Required", "Use an email address so login OTP can be sent to you.")
            return

        ok, msg = register_user(username, password, role="standard_user")
        if not ok:
            messagebox.showerror("Signup Failed", msg)
            return

        self._clear_signup()
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")
        self.username_entry.insert(0, username)
        messagebox.showinfo("Account Created", "Your account was created. Sign in with the same username and password.")
        self._show_frame(self.login_frame)

    def _handle_login(self) -> None:
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not USERNAME_PATTERN.fullmatch(username):
            messagebox.showerror("Invalid Input", USERNAME_HELP)
            return
        if len(password) < 8:
            messagebox.showerror("Invalid Input", "Password length must be at least 8 characters.")
            return

        ok, user_row, msg = login_user(username, password)
        if not ok:
            logging.getLogger("phishguard").warning("Failed login for %s", username)
            messagebox.showerror("Access Denied", msg)
            return
        if "@" not in user_row["username"]:
            messagebox.showerror("Email Required", "This account does not use an email address, so OTP cannot be sent.")
            return

        self.pending_user = user_row
        if not self._send_otp_to_pending_user():
            self.pending_user = None
            self.pending_otp = None
            return
        self._show_frame(self.otp_frame)

    def _send_otp_to_pending_user(self) -> bool:
        if not self.pending_user:
            return False
        email = str(self.pending_user["username"])
        try:
            self.pending_otp = start_email_otp(email)
        except OTPDeliveryError as exc:
            logging.getLogger("phishguard").warning("OTP delivery failed for %s: %s", email, exc)
            messagebox.showerror("OTP Email Failed", str(exc))
            return False

        self.otp_entry.delete(0, "end")
        self.otp_info_label.configure(text=f"We sent a 6-digit verification code to:\n{email}")
        log_event(email, "OTP_EMAIL", "SUCCESS", "Login OTP sent")
        return True

    def _handle_otp(self) -> None:
        ok, msg = verify_email_otp(self.pending_otp, self.otp_entry.get().strip())
        if not ok:
            username = self.pending_user["username"] if self.pending_user else None
            log_event(username, "OTP_VERIFY", "FAIL", msg)
            messagebox.showerror("OTP Failed", msg)
            return
        if not self.pending_user:
            self._show_frame(self.login_frame)
            return

        self.session = build_session(self.pending_user["username"], self.pending_user["role"])
        self.user_badge.configure(text=f"{self.session['username']} | {self.session['role']}")
        log_event(self.session["username"], "OTP_VERIFY", "SUCCESS", "Email OTP verified")
        self.pending_user = None
        self.pending_otp = None
        self._configure_session_access()
        self._refresh_history()
        self._refresh_admin_events()
        self._show_frame(self.dashboard_frame)

    def _resend_otp(self) -> None:
        if self._send_otp_to_pending_user():
            messagebox.showinfo("OTP Sent", "A new verification code was sent to your email.")

    def _cancel_otp(self) -> None:
        self.pending_user = None
        self.pending_otp = None
        self.otp_entry.delete(0, "end")
        self._show_frame(self.login_frame)

    def _sanitize_email_text(self, text: str) -> tuple[bool, str]:
        clean = text.replace("\x00", "").strip()
        if not clean:
            return False, "Email content is empty"
        if len(clean) > MAX_EMAIL_LENGTH:
            return False, f"Email is too large. Max {MAX_EMAIL_LENGTH} characters."
        if re.search(r"<\s*script", clean, flags=re.IGNORECASE):
            return False, "Script tags are blocked by input validation policy."
        return True, clean

    def _run_analysis(self) -> None:
        if not self._require_session():
            return
        valid, result = self._sanitize_email_text(self.email_text.get("1.0", "end"))
        if not valid:
            log_event(self.session["username"], "SCAN", "REJECT", result)
            messagebox.showerror("Input Validation", result)
            return

        analysis = calculate_risk(result, mode=self.analysis_mode.get())
        self.last_result = analysis
        self.last_email_text = result
        self._render_result(analysis)

        save_scan(
            username=self.session["username"],
            score=analysis.score,
            risk_level=analysis.risk_level,
            mode=analysis.analysis_mode,
            indicator_count=len(analysis.indicators),
            summary=analysis.explanation.splitlines()[0],
            email_text=result,
        )
        log_event(self.session["username"], "SCAN", "SUCCESS", f"Scan risk={analysis.risk_level}, score={analysis.score}")
        logging.getLogger("phishguard").info("Scan %s -> %s/%s", self.session["username"], analysis.score, analysis.risk_level)
        self.export_json_btn.configure(state="normal")
        self.export_pdf_btn.configure(state="normal")
        self._refresh_history()
        self._refresh_admin_events()

    def _render_result(self, analysis: AnalysisResult) -> None:
        self.score_label.configure(text=str(analysis.score), foreground=self._risk_color(analysis.risk_level))
        self.risk_label.configure(text=analysis.risk_level, foreground=self._risk_color(analysis.risk_level))
        self.risk_bar.configure(value=analysis.score)
        self.indicator_count_label.configure(text=str(len(analysis.indicators)))
        self.url_count_label.configure(text=str(len(analysis.urls)))
        self.mode_result_label.configure(text=analysis.analysis_mode.title())
        self.risk_message_label.configure(text=self._risk_message(analysis))
        self.explain_box.configure(state="normal")
        self.explain_box.delete("1.0", "end")
        self.explain_box.insert("1.0", analysis.explanation)
        self.explain_box.configure(state="disabled")

        for row in self.indicator_table.get_children():
            self.indicator_table.delete(row)
        for item in analysis.indicators:
            self.indicator_table.insert("", "end", values=(item.points, f"{item.name}: {item.evidence}"))

        self.url_list.delete(0, "end")
        for url in analysis.urls:
            self.url_list.insert("end", url)

        self.action_list.delete(0, "end")
        for action in self._recommended_actions(analysis):
            self.action_list.insert("end", action)

    def _export_json(self) -> None:
        if not self._require_session() or not self.last_result:
            return
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = self._timestamp()
        out = REPORT_DIR / f"scan_{self.session['username']}_{stamp}.json"
        payload = {
            "generated_at": self._iso_now(),
            "username": self.session["username"],
            "analysis": {
                "score": self.last_result.score,
                "risk_level": self.last_result.risk_level,
                "analysis_mode": self.last_result.analysis_mode,
                "ml_result": (
                    {
                        "phishing_probability": self.last_result.ml_result.phishing_probability,
                        "label": self.last_result.ml_result.label,
                        "confidence": self.last_result.ml_result.confidence,
                    }
                    if self.last_result.ml_result
                    else None
                ),
                "urls": self.last_result.urls,
                "indicators": [
                    {"name": i.name, "points": i.points, "evidence": i.evidence}
                    for i in self.last_result.indicators
                ],
                "explanation": self.last_result.explanation,
            },
            "email_excerpt": self.last_email_text[:1200],
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log_event(self.session["username"], "REPORT_EXPORT_JSON", "SUCCESS", f"Report written to {out.name}")
        self._refresh_admin_events()
        messagebox.showinfo("JSON Report Exported", f"Saved to:\n{out}")

    def _export_pdf(self) -> None:
        if not self._require_session() or not self.last_result:
            return
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = self._timestamp()
        out = REPORT_DIR / f"scan_{self.session['username']}_{stamp}.pdf"

        doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
        styles = getSampleStyleSheet()
        story: list = []
        result = self.last_result
        story.append(Paragraph("<b>PhishGuard Incident Analysis Report</b>", styles["Title"]))
        story.append(Paragraph(f"Generated: {self._iso_now()}", styles["Normal"]))
        story.append(Paragraph(f"Account: {self.session['username']}", styles["Normal"]))
        story.append(Spacer(1, 8))

        summary = [
            ["Score", str(result.score)],
            ["Risk", result.risk_level],
            ["Mode", result.analysis_mode.title()],
            ["Indicators", str(len(result.indicators))],
        ]
        if result.ml_result:
            summary.extend(
                [
                    ["ML Label", result.ml_result.label],
                    ["ML Phishing Probability", f"{result.ml_result.phishing_probability:.2f}"],
                    ["ML Confidence", f"{result.ml_result.confidence:.2f}"],
                ]
            )
        t1 = Table(summary, colWidths=[56 * mm, 110 * mm])
        t1.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 5)]))
        story.append(t1)
        story.append(Spacer(1, 10))

        bar = "#" * max(1, min(20, result.score // 5)) + f"  ({result.score}/100)"
        t2 = Table([["Risk Meter", bar]], colWidths=[56 * mm, 110 * mm])
        t2.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("TEXTCOLOR", (1, 0), (1, 0), colors.darkred if result.score >= 60 else colors.darkblue), ("PADDING", (0, 0), (-1, -1), 5)]))
        story.append(t2)
        story.append(Spacer(1, 10))

        story.append(Paragraph("<b>Top Indicators</b>", styles["Heading3"]))
        rows = [["Points", "Indicator Evidence"]]
        for item in sorted(result.indicators, key=lambda i: i.points, reverse=True)[:10]:
            rows.append([str(item.points), f"{item.name}: {item.evidence}"])
        t3 = Table(rows, colWidths=[22 * mm, 144 * mm])
        t3.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
        story.append(t3)
        story.append(Spacer(1, 8))

        story.append(Paragraph("<b>AI Explanation</b>", styles["Heading3"]))
        story.append(Paragraph(result.explanation.replace("\n", "<br/>"), styles["BodyText"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>Email Excerpt</b>", styles["Heading3"]))
        story.append(Paragraph(self.last_email_text[:1200].replace("\n", "<br/>"), styles["BodyText"]))

        doc.build(story)
        log_event(self.session["username"], "REPORT_EXPORT_PDF", "SUCCESS", f"Report written to {out.name}")
        self._refresh_admin_events()
        messagebox.showinfo("PDF Report Exported", f"Saved to:\n{out}")

    def _refresh_history(self) -> None:
        for row in self.history_table.get_children():
            self.history_table.delete(row)
        username = None if self._is_admin() else (self.session["username"] if self.session else None)
        if hasattr(self, "history_caption"):
            caption = "Admin view: all recent scans are shown." if self._is_admin() else "Your previous scans are stored locally for review and reporting."
            self.history_caption.configure(text=caption)
        for item in list_recent_scans(40, username=username):
            self.history_table.insert("", "end", values=(item["username"], item["score"], item["risk_level"], item["mode"], item["indicator_count"], item["created_at"]))

    def _refresh_admin_events(self) -> None:
        if not hasattr(self, "admin_events_table"):
            return
        for row in self.admin_events_table.get_children():
            self.admin_events_table.delete(row)
        if not self._is_admin():
            return
        for item in list_security_events(120):
            self.admin_events_table.insert(
                "",
                "end",
                values=(
                    item["created_at"],
                    item["username"] or "system",
                    item["event_type"],
                    item["status"],
                    item["details"],
                ),
            )

    def _set_email_text(self, value: str, source: str = "Manual input") -> None:
        self.email_text.delete("1.0", "end")
        self.email_text.insert("1.0", value)
        self._update_input_meta(source)

    def _update_input_meta(self, source: str = "Manual input") -> None:
        if not hasattr(self, "input_meta_label"):
            return
        content = self.email_text.get("1.0", "end-1c")
        self.input_meta_label.configure(text=f"{source} | {len(content):,} characters")

    def _load_email_file(self) -> None:
        if not self._require_session():
            return
        filename = filedialog.askopenfilename(
            title="Open email text",
            filetypes=[("Email or text files", "*.eml *.txt"), ("All files", "*.*")],
        )
        if not filename:
            return
        path = Path(filename)
        if path.suffix.lower() not in SUPPORTED_EMAIL_FILES:
            messagebox.showerror("Unsupported File", "Please choose a .txt or .eml file.")
            return
        if path.stat().st_size > MAX_EMAIL_LENGTH * 3:
            messagebox.showerror("File Too Large", f"Maximum supported file size is about {MAX_EMAIL_LENGTH} characters.")
            return

        try:
            content = self._read_email_file(path)
        except OSError as exc:
            messagebox.showerror("File Error", f"Could not read file:\n{exc}")
            return

        valid, result = self._sanitize_email_text(content)
        if not valid:
            messagebox.showerror("Input Validation", result)
            return
        self._set_email_text(result, f"Loaded file: {path.name}")

    def _read_email_file(self, path: Path) -> str:
        data = path.read_bytes()
        if path.suffix.lower() == ".txt":
            return data.decode("utf-8", errors="replace")

        message = BytesParser(policy=policy.default).parsebytes(data)
        headers = []
        for name in ("From", "Reply-To", "Subject"):
            value = message.get(name)
            if value:
                headers.append(f"{name}: {value}")

        body_parts: list[str] = []
        attachments: list[str] = []
        if message.is_multipart():
            for part in message.walk():
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
                if part.get_content_type() == "text/plain" and not filename:
                    body_parts.append(part.get_content())
        else:
            body_parts.append(message.get_content())

        attachment_lines = [f"Attachment: {name}" for name in attachments]
        return "\n".join(headers + body_parts + attachment_lines)

    def _is_admin(self) -> bool:
        return bool(self.session and self.session.get("role") == "admin")

    def _configure_session_access(self) -> None:
        self.export_json_btn.configure(state="disabled")
        self.export_pdf_btn.configure(state="disabled")
        admin_tab_id = str(self.admin_tab)

        if not self.session:
            self.user_badge.configure(text="")
            self.workspace_badge.configure(text="Personal workspace")
            if admin_tab_id in self.notebook.tabs():
                self.notebook.forget(self.admin_tab)
            self._refresh_admin_events()
            return

        self.user_badge.configure(text=f"{self.session['username']} | {self.session['role']}")
        if self._is_admin():
            self.workspace_badge.configure(text="Admin workspace")
            if admin_tab_id not in self.notebook.tabs():
                self.notebook.add(self.admin_tab, text="Security Events")
        else:
            self.workspace_badge.configure(text="Personal workspace")
            if admin_tab_id in self.notebook.tabs():
                self.notebook.forget(self.admin_tab)

    def _recommended_actions(self, analysis: AnalysisResult) -> list[str]:
        if analysis.score >= 60:
            return [
                "Do not click links or open attachments.",
                "Verify the sender using a trusted channel.",
                "Report the email to IT/security.",
            ]
        if analysis.score >= 35:
            return [
                "Treat as suspicious until verified.",
                "Check sender, reply-to, links, and attachments.",
                "Do not share credentials or payment details.",
            ]
        return [
            "No major red flags detected.",
            "Stay cautious with unexpected requests.",
            "Verify links before entering sensitive data.",
        ]

    def _risk_message(self, analysis: AnalysisResult) -> str:
        if analysis.score >= 80:
            return "Critical risk: this email has multiple high-confidence phishing signals and should be reported immediately."
        if analysis.score >= 60:
            return "High risk: the message contains strong phishing indicators. Avoid interaction until verified."
        if analysis.score >= 35:
            return "Medium risk: suspicious patterns were found. Review the evidence before taking action."
        return "Low risk: no strong phishing pattern was found, but unexpected emails should still be verified."

    def _require_session(self) -> bool:
        if not self.session:
            self._show_frame(self.login_frame)
            return False
        if session_expired(self.session):
            messagebox.showwarning("Session Expired", "Your secure session expired. Please login again.")
            self._logout()
            return False
        return True

    def _session_guard(self) -> None:
        if self.session and session_expired(self.session):
            log_event(self.session["username"], "SESSION", "TIMEOUT", "Session expired due to inactivity")
            self._logout(show_message=True)
        self.after(5000, self._session_guard)

    def _logout(self, show_message: bool = False) -> None:
        if self.session:
            log_event(self.session["username"], "LOGOUT", "SUCCESS", "User ended session")
        self.session = None
        self.pending_user = None
        self.pending_otp = None
        self.last_result = None
        self.last_email_text = ""
        self._configure_session_access()
        self._clear_login()
        self.otp_entry.delete(0, "end")
        self._show_frame(self.login_frame)
        if show_message:
            messagebox.showinfo("Session Closed", "Session ended. Please sign in again.")

    def _risk_color(self, risk_level: str) -> str:
        return {
            "Low": "#16a34a",
            "Medium": "#d97706",
            "High": "#dc2626",
            "Critical": "#7f1d1d",
        }.get(risk_level, "#2563eb")

    def _toggle_theme(self) -> None:
        self.colors = DARK_THEME if self.dark_mode.get() else LIGHT_THEME
        self.configure(bg=self.colors["bg"])
        self._setup_styles()
        for widget in self.theme_widgets:
            try:
                widget.configure(
                    bg=self.colors["field"],
                    fg=self.colors["text"],
                    insertbackground=self.colors["text"],
                    selectbackground=self.colors["secondary"],
                    selectforeground="#ffffff",
                )
            except tk.TclError:
                widget.configure(bg=self.colors["field"], fg=self.colors["text"])
        if self.last_result:
            self._render_result(self.last_result)

    def _timestamp(self) -> str:
        from datetime import datetime

        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _iso_now(self) -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()


def launch_app() -> None:
    app = PhishGuardApp()
    app.mainloop()


if __name__ == "__main__":
    launch_app()
