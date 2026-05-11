from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import tkinter as tk
from tkinter import messagebox, ttk

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from auth.login import login_user
from auth.otp import get_demo_otp, verify_otp
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
DEMO_MODE = True
MAX_EMAIL_LENGTH = 50000

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
        self.session: dict | None = None
        self.last_result: AnalysisResult | None = None
        self.last_email_text: str = ""
        self.analysis_mode = tk.StringVar(value="hybrid")

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
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#f4f7fb")
        self.style.configure("Card.TFrame", background="#ffffff")
        self.style.configure("Header.TLabel", font=("Avenir Next", 26, "bold"), foreground="#1f2937", background="#f4f7fb")
        self.style.configure("Muted.TLabel", font=("Avenir Next", 11), foreground="#5b6470", background="#f4f7fb")
        self.style.configure("CardTitle.TLabel", font=("Avenir Next", 14, "bold"), foreground="#111827", background="#ffffff")
        self.style.configure("Primary.TButton", font=("Avenir Next", 11, "bold"), padding=10)
        self.style.configure("Secondary.TButton", font=("Avenir Next", 10), padding=8)
        self.style.configure("Score.TLabel", font=("Avenir Next", 34, "bold"), background="#ffffff")
        self.style.configure("Treeview", rowheight=28, font=("Avenir Next", 10))
        self.style.configure("Treeview.Heading", font=("Avenir Next", 10, "bold"))

    def _build_shell(self) -> None:
        self.root_frame = ttk.Frame(self)
        self.root_frame.pack(fill="both", expand=True)

        self.login_frame = ttk.Frame(self.root_frame, style="TFrame")
        self.otp_frame = ttk.Frame(self.root_frame, style="TFrame")
        self.dashboard_frame = ttk.Frame(self.root_frame, style="TFrame")
        for frame in (self.login_frame, self.otp_frame, self.dashboard_frame):
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._build_login()
        self._build_otp()
        self._build_dashboard()

    def _show_frame(self, frame: ttk.Frame) -> None:
        frame.tkraise()

    def _build_login(self) -> None:
        card = ttk.Frame(self.login_frame, style="Card.TFrame", padding=32)
        card.place(relx=0.5, rely=0.5, anchor="center", width=560, height=540)

        ttk.Label(card, text="PhishGuard", style="Header.TLabel").pack(anchor="center", pady=(4, 0))
        ttk.Label(card, text="AI-Assisted Phishing Email Detection", style="Muted.TLabel").pack(anchor="center", pady=(0, 24))
        ttk.Label(card, text="Secure Login", style="CardTitle.TLabel").pack(anchor="w")

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x", pady=16)
        ttk.Label(form, text="Username", style="Muted.TLabel").pack(anchor="w")
        self.username_entry = ttk.Entry(form, font=("Avenir Next", 12))
        self.username_entry.pack(fill="x", pady=(2, 14), ipady=6)

        ttk.Label(form, text="Password", style="Muted.TLabel").pack(anchor="w")
        self.password_entry = ttk.Entry(form, show="*", font=("Avenir Next", 12))
        self.password_entry.pack(fill="x", pady=(2, 20), ipady=6)

        row = ttk.Frame(form, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Sign In", style="Primary.TButton", command=self._handle_login).pack(side="left")
        ttk.Button(row, text="Clear", style="Secondary.TButton", command=self._clear_login).pack(side="left", padx=8)

        demo = (
            "Demo Accounts\n"
            "admin / Admin@123 (Admin)\n"
            "analyst / Analyst@123 (Security Analyst)\n"
            "user / User@123 (Standard User)"
        )
        ttk.Label(card, text=demo, style="Muted.TLabel", justify="left").pack(anchor="w", pady=(28, 0))

    def _build_otp(self) -> None:
        card = ttk.Frame(self.otp_frame, style="Card.TFrame", padding=32)
        card.place(relx=0.5, rely=0.5, anchor="center", width=560, height=400)
        ttk.Label(card, text="Two-Factor Authentication", style="Header.TLabel").pack(anchor="center")
        self.otp_info_label = ttk.Label(card, text="Enter the 6-digit OTP.", style="Muted.TLabel", justify="center")
        self.otp_info_label.pack(anchor="center", pady=(8, 20))
        self.otp_entry = ttk.Entry(card, font=("Avenir Next", 20), justify="center")
        self.otp_entry.pack(fill="x", ipady=8)

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=20)
        ttk.Button(row, text="Verify OTP", style="Primary.TButton", command=self._handle_otp).pack(side="left")
        ttk.Button(row, text="Back", style="Secondary.TButton", command=lambda: self._show_frame(self.login_frame)).pack(side="left", padx=8)
        if DEMO_MODE:
            ttk.Button(row, text="Use Demo OTP", style="Secondary.TButton", command=self._fill_demo_otp).pack(side="left")

    def _build_dashboard(self) -> None:
        header = ttk.Frame(self.dashboard_frame, style="TFrame", padding=(20, 14))
        header.pack(fill="x")
        ttk.Label(header, text="PhishGuard Security Dashboard", style="Header.TLabel").pack(side="left")
        self.user_badge = ttk.Label(header, text="", style="Muted.TLabel")
        self.user_badge.pack(side="right", padx=10)
        ttk.Button(header, text="Logout", style="Secondary.TButton", command=self._logout).pack(side="right")

        notebook = ttk.Notebook(self.dashboard_frame)
        notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.analysis_tab = ttk.Frame(notebook, style="TFrame")
        self.history_tab = ttk.Frame(notebook, style="TFrame")
        self.events_tab = ttk.Frame(notebook, style="TFrame")
        notebook.add(self.analysis_tab, text="Email Analysis")
        notebook.add(self.history_tab, text="Scan History")
        notebook.add(self.events_tab, text="Security Events")
        self._build_analysis_tab()
        self._build_history_tab()
        self._build_events_tab()

    def _build_analysis_tab(self) -> None:
        left = ttk.Frame(self.analysis_tab, style="Card.TFrame", padding=16)
        left.place(relx=0.01, rely=0.02, relwidth=0.56, relheight=0.96)
        ttk.Label(left, text="Email / Header Input", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(left, text="Paste full email content including headers for better accuracy.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.email_text = tk.Text(left, wrap="word", font=("Menlo", 11), bg="#fcfcfd", fg="#1f2937", relief="flat", height=26)
        self.email_text.pack(fill="both", expand=True)

        row = ttk.Frame(left, style="Card.TFrame")
        row.pack(fill="x", pady=(10, 0))
        ttk.Button(row, text="Analyze Email", style="Primary.TButton", command=self._run_analysis).pack(side="left")
        ttk.Button(row, text="Load Phishing Sample", style="Secondary.TButton", command=lambda: self._set_email_text(SAMPLE_PHISH)).pack(side="left", padx=6)
        ttk.Button(row, text="Load Legit Sample", style="Secondary.TButton", command=lambda: self._set_email_text(SAMPLE_LEGIT)).pack(side="left", padx=6)
        ttk.Button(row, text="Clear", style="Secondary.TButton", command=lambda: self._set_email_text("")).pack(side="left", padx=6)

        mode_row = ttk.Frame(left, style="Card.TFrame")
        mode_row.pack(fill="x", pady=(10, 0))
        ttk.Label(mode_row, text="Detection Mode:", style="Muted.TLabel").pack(side="left", padx=(0, 10))
        ttk.Radiobutton(mode_row, text="Hybrid", value="hybrid", variable=self.analysis_mode).pack(side="left")
        ttk.Radiobutton(mode_row, text="Heuristic", value="heuristic", variable=self.analysis_mode).pack(side="left", padx=8)
        ttk.Radiobutton(mode_row, text="ML", value="ml", variable=self.analysis_mode).pack(side="left", padx=8)

        right = ttk.Frame(self.analysis_tab, style="Card.TFrame", padding=16)
        right.place(relx=0.59, rely=0.02, relwidth=0.4, relheight=0.96)
        ttk.Label(right, text="Risk Summary", style="CardTitle.TLabel").pack(anchor="w")
        meter_wrap = ttk.Frame(right, style="Card.TFrame")
        meter_wrap.pack(fill="x", pady=8)
        self.score_label = ttk.Label(meter_wrap, text="0", style="Score.TLabel", foreground="#2563eb")
        self.score_label.pack(side="left")
        self.risk_label = ttk.Label(meter_wrap, text="Low", font=("Avenir Next", 16, "bold"), background="#ffffff", foreground="#2563eb")
        self.risk_label.pack(side="left", padx=10)
        self.risk_bar = ttk.Progressbar(right, orient="horizontal", mode="determinate", length=320)
        self.risk_bar.pack(fill="x", pady=(0, 12))

        ttk.Label(right, text="AI Explanation", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))
        self.explain_box = tk.Text(right, wrap="word", height=8, font=("Avenir Next", 10), bg="#fbfbfd", relief="flat")
        self.explain_box.pack(fill="x")
        self.explain_box.configure(state="disabled")

        ttk.Label(right, text="Indicators", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 6))
        self.indicator_table = ttk.Treeview(right, columns=("points", "evidence"), show="headings", height=8)
        self.indicator_table.heading("points", text="Points")
        self.indicator_table.heading("evidence", text="Evidence")
        self.indicator_table.column("points", width=70, anchor="center")
        self.indicator_table.column("evidence", width=300)
        self.indicator_table.pack(fill="both", expand=True)

        ttk.Label(right, text="Detected URLs", style="CardTitle.TLabel").pack(anchor="w", pady=(10, 6))
        self.url_list = tk.Listbox(right, height=4, font=("Menlo", 10), relief="flat")
        self.url_list.pack(fill="x")

        export_row = ttk.Frame(right, style="Card.TFrame")
        export_row.pack(anchor="e", pady=(10, 0))
        self.export_json_btn = ttk.Button(export_row, text="Export JSON", style="Secondary.TButton", command=self._export_json)
        self.export_json_btn.pack(side="left", padx=4)
        self.export_pdf_btn = ttk.Button(export_row, text="Export PDF", style="Secondary.TButton", command=self._export_pdf)
        self.export_pdf_btn.pack(side="left", padx=4)
        self.export_ssdlc_btn = ttk.Button(export_row, text="Generate SSDLC Artifacts", style="Secondary.TButton", command=self._generate_ssdlc)
        self.export_ssdlc_btn.pack(side="left", padx=4)
        self.export_json_btn.configure(state="disabled")
        self.export_pdf_btn.configure(state="disabled")

    def _build_history_tab(self) -> None:
        card = ttk.Frame(self.history_tab, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True, padx=10, pady=10)
        header = ttk.Frame(card, style="Card.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Recent Scan Activity", style="CardTitle.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh", style="Secondary.TButton", command=self._refresh_history).pack(side="right")

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

    def _build_events_tab(self) -> None:
        card = ttk.Frame(self.events_tab, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True, padx=10, pady=10)
        header = ttk.Frame(card, style="Card.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Security Audit Events", style="CardTitle.TLabel").pack(side="left")
        self.refresh_events_btn = ttk.Button(header, text="Refresh", style="Secondary.TButton", command=self._refresh_events)
        self.refresh_events_btn.pack(side="right")
        self.events_table = ttk.Treeview(card, columns=("user", "event", "status", "details", "time"), show="headings")
        for col, text, width in [
            ("user", "User", 100),
            ("event", "Event", 140),
            ("status", "Status", 90),
            ("details", "Details", 470),
            ("time", "Time (UTC)", 260),
        ]:
            self.events_table.heading(col, text=text)
            self.events_table.column(col, width=width, anchor="center" if col in {"user", "event", "status"} else "w")
        self.events_table.pack(fill="both", expand=True, pady=(10, 0))

    def _clear_login(self) -> None:
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")

    def _handle_login(self) -> None:
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            messagebox.showerror("Invalid Input", "Username must be 3-32 chars with letters, numbers, ., _, or -")
            return
        if len(password) < 8:
            messagebox.showerror("Invalid Input", "Password length must be at least 8 characters.")
            return

        ok, user_row, msg = login_user(username, password)
        if not ok:
            logging.getLogger("phishguard").warning("Failed login for %s", username)
            messagebox.showerror("Access Denied", msg)
            return

        self.pending_user = user_row
        self.otp_entry.delete(0, "end")
        self.otp_info_label.configure(text=f"Username: {username}\nEnter your 6-digit OTP code.")
        self._show_frame(self.otp_frame)

    def _fill_demo_otp(self) -> None:
        if not self.pending_user:
            messagebox.showwarning("No Session", "Please authenticate username/password first.")
            return
        otp = get_demo_otp(self.pending_user["username"])
        if not otp:
            messagebox.showerror("OTP Error", "Unable to generate demo OTP")
            return
        self.otp_entry.delete(0, "end")
        self.otp_entry.insert(0, otp)

    def _handle_otp(self) -> None:
        if not self.pending_user:
            self._show_frame(self.login_frame)
            return
        code = self.otp_entry.get().strip()
        ok, msg = verify_otp(self.pending_user["username"], code)
        if not ok:
            messagebox.showerror("2FA Failed", msg)
            return

        self.session = build_session(self.pending_user["username"], self.pending_user["role"])
        self.user_badge.configure(text=f"User: {self.session['username']} | Role: {self.session['role']}")
        self.pending_user = None
        self._refresh_history()
        self._refresh_events()
        self._show_frame(self.dashboard_frame)

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
        self._refresh_events()

    def _render_result(self, analysis: AnalysisResult) -> None:
        self.score_label.configure(text=str(analysis.score), foreground=self._risk_color(analysis.risk_level))
        self.risk_label.configure(text=analysis.risk_level, foreground=self._risk_color(analysis.risk_level))
        self.risk_bar.configure(value=analysis.score)
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
        messagebox.showinfo("JSON Report Exported", f"Saved to:\n{out}")
        self._refresh_events()

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
        story.append(Paragraph(f"Analyst: {self.session['username']}", styles["Normal"]))
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
        messagebox.showinfo("PDF Report Exported", f"Saved to:\n{out}")
        self._refresh_events()

    def _generate_ssdlc(self) -> None:
        if not self._require_session():
            return
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = self._timestamp()
        threat_path = REPORT_DIR / f"threat_model_{stamp}.md"
        tests_path = REPORT_DIR / f"security_test_cases_{stamp}.md"
        today = self._iso_now().split("T", 1)[0]

        threat_path.write_text(
            f"# STRIDE Threat Model - PhishGuard\n\nGenerated: {today}\n\n"
            "## Architecture Components\n"
            "- GUI Client (Tkinter)\n"
            "- Authentication Module (bcrypt + TOTP)\n"
            "- Analysis Engine (heuristic + optional ML)\n"
            "- SQLite Data Store\n"
            "- Report Export Service\n"
            "- Security Audit Logger\n\n"
            "## STRIDE Summary\n"
            "- Spoofing: mitigated by password hashing + OTP\n"
            "- Tampering: mitigated by audit logs\n"
            "- Repudiation: mitigated by timestamped events\n"
            "- Information Disclosure: mitigated by encrypted OTP secrets\n"
            "- DoS: mitigated by input size controls\n"
            "- Elevation of Privilege: mitigated by RBAC checks\n",
            encoding="utf-8",
        )

        tests_path.write_text(
            f"# Security Test Cases - PhishGuard\n\nGenerated: {today}\n\n"
            "## Authentication\n"
            "- AUTH-01: Valid password + OTP should grant access\n"
            "- AUTH-02: Wrong password should be denied and logged\n"
            "- AUTH-03: Wrong OTP should be denied and logged\n"
            "- AUTH-04: Non-admin cannot view security events\n\n"
            "## Detection\n"
            "- DET-01: Phishing sample should score High/Critical\n"
            "- DET-02: Legit sample should score lower than phishing sample\n"
            "- DET-03: URL shortener + HTTP should trigger indicators\n\n"
            "## Reporting\n"
            "- RPT-01: JSON export creates file in reports\n"
            "- RPT-02: PDF export creates file in reports\n"
            "- RPT-03: SSDLC artifact generation creates markdown files\n",
            encoding="utf-8",
        )
        log_event(self.session["username"], "SSDLC_ARTIFACTS", "SUCCESS", f"Generated {threat_path.name} and {tests_path.name}")
        messagebox.showinfo("SSDLC Artifacts Generated", f"Threat model:\n{threat_path}\n\nSecurity tests:\n{tests_path}")
        self._refresh_events()

    def _refresh_history(self) -> None:
        for row in self.history_table.get_children():
            self.history_table.delete(row)
        for item in list_recent_scans(40):
            self.history_table.insert("", "end", values=(item["username"], item["score"], item["risk_level"], item["mode"], item["indicator_count"], item["created_at"]))

    def _refresh_events(self) -> None:
        if not self.session:
            return
        is_admin = self.session["role"] == "admin"
        self.refresh_events_btn.configure(state="normal" if is_admin else "disabled")
        for row in self.events_table.get_children():
            self.events_table.delete(row)
        if not is_admin:
            self.events_table.insert("", "end", values=("-", "ACCESS", "DENIED", "Admin role required to view security events", "-"))
            return
        for item in list_security_events(80):
            self.events_table.insert("", "end", values=(item["username"] or "system", item["event_type"], item["status"], item["details"], item["created_at"]))

    def _set_email_text(self, value: str) -> None:
        self.email_text.delete("1.0", "end")
        self.email_text.insert("1.0", value)

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
        self.last_result = None
        self.last_email_text = ""
        self._clear_login()
        self.otp_entry.delete(0, "end")
        self._show_frame(self.login_frame)
        if show_message:
            messagebox.showinfo("Session Closed", "Session ended. Please sign in again.")

    def _risk_color(self, risk_level: str) -> str:
        return {
            "Low": "#2563eb",
            "Medium": "#d97706",
            "High": "#dc2626",
            "Critical": "#7f1d1d",
        }.get(risk_level, "#2563eb")

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
