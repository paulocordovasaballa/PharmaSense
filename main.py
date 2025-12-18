import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import database
import itertools
from datetime import datetime
import threading

# --- 1. IMPORT MODULES ---
# Try importing local modules, handle errors gracefully if files are missing
try:
    from api_checker import DDInterChecker
except ImportError:
    messagebox.showerror("Error", "Missing 'api_checker.py'. Please ensure all files are in the same directory.")
    raise

try:
    from external_apis import MedicalAPI
except ImportError:
    MedicalAPI = None # API features will be disabled if file is missing

# Check for ReportLab (PDF Generation)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# --- 2. CONFIGURATION & THEME ---
APP_TITLE = "PharmaSense"
WINDOW_SIZE = "1100x750"

# Modern Color Palette
COLOR_PRIMARY = "#00796B"    # Teal
COLOR_PRIMARY_HOVER = "#004D40"
COLOR_SECONDARY = "#CFD8DC"  # Light Blue Grey
COLOR_BG = "#ECEFF1"         # Very light grey background
COLOR_WHITE = "#FFFFFF"
COLOR_DANGER = "#D32F2F"     # Red
COLOR_TEXT = "#263238"       # Dark Slate

# Fonts
FONT_MAIN = ("Segoe UI", 11)
FONT_BOLD = ("Segoe UI", 11, "bold")
FONT_TITLE = ("Segoe UI", 24, "bold")
FONT_HEADER = ("Segoe UI", 16, "bold")
FONT_MONO = ("Consolas", 10)

class PharmaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(900, 600)
        self.configure(bg=COLOR_BG)
        
        # --- STYLING ---
        style = ttk.Style()
        style.theme_use('clam')

        # Frames
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background=COLOR_WHITE, relief="flat")

        # Labels
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT, font=FONT_MAIN)
        style.configure("Card.TLabel", background=COLOR_WHITE, foreground=COLOR_TEXT, font=FONT_MAIN)
        style.configure("Header.TLabel", font=FONT_HEADER, background=COLOR_WHITE, foreground=COLOR_PRIMARY)
        style.configure("Title.TLabel", font=FONT_TITLE, background=COLOR_WHITE, foreground=COLOR_PRIMARY)
        style.configure("Link.TLabel", foreground=COLOR_PRIMARY, font=("Segoe UI", 10, "underline"))

        # Buttons (Semantic Colors)
        style.configure("Primary.TButton", font=FONT_BOLD, background=COLOR_PRIMARY, foreground=COLOR_WHITE, borderwidth=0, focuscolor=COLOR_PRIMARY_HOVER)
        style.map("Primary.TButton", background=[("active", COLOR_PRIMARY_HOVER)])

        style.configure("Secondary.TButton", font=FONT_MAIN, background=COLOR_SECONDARY, foreground=COLOR_TEXT, borderwidth=0)
        style.map("Secondary.TButton", background=[("active", "#B0BEC5")])

        style.configure("Danger.TButton", font=FONT_BOLD, background=COLOR_DANGER, foreground=COLOR_WHITE, borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#B71C1C")])

        # --- DATABASE ---
        self.conn = database.create_connection()
        if self.conn:
            database.setup_database(self.conn)
        else:
            messagebox.showerror("Error", "Database Connection Failed")
            self.destroy()

        # --- APIS ---
        self.checker = DDInterChecker()
        self.med_api = MedicalAPI() if MedicalAPI else None
        self.current_user_id = None

        # --- LAYOUT ---
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginPage, SignUpPage, DashboardPage):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        if page_name == "DashboardPage":
            frame.initialize_data()

    def login_success(self, user_id):
        self.current_user_id = user_id
        self.show_frame("DashboardPage")

    def logout(self):
        self.current_user_id = None
        self.frames["DashboardPage"].reset_ui()
        self.show_frame("LoginPage")


class LoginPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        center_frame = ttk.Frame(self)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        card = ttk.Frame(center_frame, style="Card.TFrame", padding=50)
        card.pack(fill="both", expand=True)
        card.configure(borderwidth=1, relief="solid")

        ttk.Label(card, text="PharmaSense", style="Title.TLabel").pack(pady=(0, 5))
        ttk.Label(card, text="Clinical Decision Support System", style="Card.TLabel", foreground="#78909C").pack(pady=(0, 40))

        ttk.Label(card, text="Username", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.user_entry = ttk.Entry(card, width=40, font=FONT_MAIN)
        self.user_entry.pack(pady=(5, 15))

        ttk.Label(card, text="Password", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.pass_entry = ttk.Entry(card, show="•", width=40, font=FONT_MAIN)
        self.pass_entry.pack(pady=(5, 25))

        ttk.Button(card, text="LOG IN", style="Primary.TButton", command=self.handle_login).pack(fill="x", pady=10, ipady=5)
        
        reg_lbl = ttk.Label(card, text="Create New Account", style="Link.TLabel", cursor="hand2")
        reg_lbl.pack(pady=10)
        reg_lbl.bind("<Button-1>", lambda e: controller.show_frame("SignUpPage"))

    def handle_login(self):
        u = self.user_entry.get()
        p = self.pass_entry.get()
        uid = database.authenticate_user(self.controller.conn, u, p)
        if uid:
            self.user_entry.delete(0, tk.END)
            self.pass_entry.delete(0, tk.END)
            self.controller.login_success(uid)
        else:
            messagebox.showerror("Login Failed", "Invalid Username or Password")


class SignUpPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        center_frame = ttk.Frame(self)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        card = ttk.Frame(center_frame, style="Card.TFrame", padding=50)
        card.pack(fill="both", expand=True)
        card.configure(borderwidth=1, relief="solid")

        ttk.Label(card, text="Create Account", style="Title.TLabel").pack(pady=(0, 30))

        ttk.Label(card, text="Choose Username", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.user_entry = ttk.Entry(card, width=40, font=FONT_MAIN)
        self.user_entry.pack(pady=(5, 15))

        ttk.Label(card, text="Choose Password", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.pass_entry = ttk.Entry(card, show="•", width=40, font=FONT_MAIN)
        self.pass_entry.pack(pady=(5, 25))

        ttk.Button(card, text="SIGN UP", style="Primary.TButton", command=self.handle_signup).pack(fill="x", pady=10, ipady=5)
        
        back_lbl = ttk.Label(card, text="Back to Login", style="Link.TLabel", cursor="hand2")
        back_lbl.pack(pady=10)
        back_lbl.bind("<Button-1>", lambda e: controller.show_frame("LoginPage"))

    def handle_signup(self):
        if database.register_user(self.controller.conn, self.user_entry.get(), self.pass_entry.get()):
            messagebox.showinfo("Success", "Account Created Successfully")
            self.controller.show_frame("LoginPage")
        else:
            messagebox.showerror("Error", "Username is already taken.")


class DashboardPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_drugs = []
        self.all_options = []

        # --- Top Header ---
        header = ttk.Frame(self, padding=(20, 15))
        header.pack(fill="x")
        
        logo_frame = ttk.Frame(header)
        logo_frame.pack(side="left")
        ttk.Label(logo_frame, text="Pharma", font=("Segoe UI", 18, "bold"), foreground=COLOR_TEXT).pack(side="left")
        ttk.Label(logo_frame, text="Sense", font=("Segoe UI", 18, "bold"), foreground=COLOR_PRIMARY).pack(side="left")

        btn_frame = ttk.Frame(header)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="History Log", style="Secondary.TButton", command=self.open_history).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Logout", style="Danger.TButton", command=controller.logout).pack(side="left", padx=5)

        # --- Main Layout ---
        main_content = ttk.Frame(self, padding=20)
        main_content.pack(fill="both", expand=True)
        main_content.columnconfigure(1, weight=1)
        main_content.rowconfigure(0, weight=1)

        # --- Sidebar ---
        sidebar = ttk.Frame(main_content, width=320, padding=20, style="Card.TFrame")
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        sidebar.pack_propagate(False) 
        sidebar.configure(borderwidth=1, relief="solid")

        ttk.Label(sidebar, text="Prescription Entry", style="Header.TLabel").pack(anchor="w", pady=(0, 20))
        
        ttk.Label(sidebar, text="Search Drug Name:", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.combo = ttk.Combobox(sidebar, font=FONT_MAIN)
        self.combo.pack(fill="x", pady=(5, 15))
        self.combo.bind('<KeyRelease>', self.filter_drugs)

        btn_row = ttk.Frame(sidebar, style="Card.TFrame")
        btn_row.pack(fill="x", pady=5)
        ttk.Button(btn_row, text="Add Drug", style="Primary.TButton", command=self.add_drug).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(btn_row, text="Clear", style="Secondary.TButton", command=self.reset_ui).pack(side="left", fill="x", expand=True)

        ttk.Label(sidebar, text="Current List:", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w", pady=(25, 10))
        
        list_frame = tk.Frame(sidebar, background="#B0BEC5", bd=1)
        list_frame.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(list_frame, font=FONT_MAIN, borderwidth=0, highlightthickness=0, bg="#FAFAFA", selectbackground=COLOR_PRIMARY_HOVER)
        self.listbox.pack(fill="both", expand=True, padx=1, pady=1)

        ttk.Button(sidebar, text="RUN SAFETY CHECK", style="Primary.TButton", command=self.start_analysis_thread).pack(fill="x", pady=20, ipady=10)

        # --- Results Area ---
        results_area = ttk.Frame(main_content, style="Card.TFrame", padding=20)
        results_area.grid(row=0, column=1, sticky="nsew")
        results_area.configure(borderwidth=1, relief="solid")

        ttk.Label(results_area, text="Analysis Report", style="Header.TLabel").pack(anchor="w", pady=(0, 15))

        report_frame = ttk.Frame(results_area, style="Card.TFrame")
        report_frame.pack(fill="both", expand=True)
        
        v_scroll = ttk.Scrollbar(report_frame)
        v_scroll.pack(side="right", fill="y")

        self.report = tk.Text(
            report_frame, font=FONT_MONO, borderwidth=0, highlightthickness=0, 
            padx=15, pady=15, wrap="word", bg="#FAFAFA", state="disabled", yscrollcommand=v_scroll.set
        )
        self.report.pack(side="left", fill="both", expand=True)
        v_scroll.config(command=self.report.yview)

        self.report.tag_config("FDA", foreground="#6A1B9A", font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self.report.tag_config("MAJOR", foreground=COLOR_DANGER, font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self.report.tag_config("SAFE", foreground="#2E7D32", font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self.report.tag_config("HEADER", font=(FONT_MONO[0], 12, "bold"))

    def initialize_data(self):
        self.all_options = self.controller.checker.get_drug_list()
        self.combo['values'] = self.all_options

    def filter_drugs(self, event):
        if event.keysym in ('Up', 'Down', 'Left', 'Right', 'Return'): return
        typed = self.combo.get().lower()
        if typed == '':
            self.combo['values'] = self.all_options
        else:
            self.combo['values'] = [x for x in self.all_options if typed in x.lower()]

    def add_drug(self):
        val = self.combo.get().strip()
        if val and val not in self.selected_drugs:
            self.selected_drugs.append(val)
            self.listbox.insert(tk.END, f"  • {val}")
            self.combo.set('')
            self.combo['values'] = self.all_options

    def reset_ui(self):
        self.selected_drugs = []
        self.listbox.delete(0, tk.END)
        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        self.report.config(state="disabled")

    def start_analysis_thread(self):
        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        
        if len(self.selected_drugs) < 2:
            self.report.insert(tk.END, "⚠ Please add at least 2 drugs to the list for interaction checking.")
            self.report.config(state="disabled")
            return
            
        self.report.insert(tk.END, "⏳ Connecting to FDA Database and Local Registry...\n")
        self.report.config(state="disabled")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        fda_notes = []
        if self.controller.med_api:
            for drug in self.selected_drugs:
                w = self.controller.med_api.get_fda_warnings(drug)
                if w: fda_notes.append(f"• {drug}: {w}")

        interaction_notes = []
        has_interaction = False
        logs_to_save = []
        
        if len(self.selected_drugs) >= 2:
            for d1, d2 in itertools.combinations(self.selected_drugs, 2):
                res = self.controller.checker.check_interaction(d1, d2)
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if res:
                    has_interaction = True
                    for r in res:
                        sev = r.get('severity', 'Unknown')
                        desc = r.get('description', '')
                        interaction_notes.append((d1, d2, sev, desc))
                        logs_to_save.append((d1, d2, sev, desc, ts))
                else:
                    logs_to_save.append((d1, d2, "Safe", "No interactions detected", ts))

        self.after(0, lambda: self.display_results(fda_notes, interaction_notes, has_interaction, logs_to_save))

    def display_results(self, fda_notes, interaction_notes, has_interaction, logs_to_save):
        for item in logs_to_save:
            try:
                database.log_interaction(self.controller.conn, self.controller.current_user_id, item[0], item[1], item[2], item[3], item[4])
            except Exception as e:
                print(f"Log Error: {e}")

        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        
        if fda_notes:
            self.report.insert(tk.END, "OFFICIAL FDA WARNINGS\n", "HEADER")
            self.report.insert(tk.END, "─"*40 + "\n", "FDA")
            for n in fda_notes: 
                self.report.insert(tk.END, n + "\n\n")
            self.report.insert(tk.END, "\n")
        
        if has_interaction:
            self.report.insert(tk.END, "INTERACTIONS DETECTED\n", "MAJOR")
            self.report.insert(tk.END, "─"*40 + "\n")
            for d1, d2, sev, desc in interaction_notes:
                self.report.insert(tk.END, f"⚠ {d1} + {d2}\n", "MAJOR")
                self.report.insert(tk.END, f"Severity: {sev}\n")
                self.report.insert(tk.END, f"Details: {desc}\n\n")
        else:
            self.report.insert(tk.END, "✅ No interactions found in local database.\n", "SAFE")
            self.report.insert(tk.END, "The selected combination appears safe based on current records.")
        
        self.report.config(state="disabled")

    def open_history(self):
        try:
            rows = database.get_user_history(self.controller.conn, self.controller.current_user_id)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
            
        if not rows:
            messagebox.showinfo("History", "No history records found.")
            return

        win = tk.Toplevel(self)
        win.title("History Log")
        win.geometry("900x600")
        win.configure(bg=COLOR_BG)

        style = ttk.Style()
        style.configure("Treeview", font=FONT_MAIN, rowheight=25)
        style.configure("Treeview.Heading", font=FONT_BOLD)

        cols = ("Date", "Pair", "Severity", "Details")
        tree = ttk.Treeview(win, columns=cols, show='headings')
        for c in cols: tree.heading(c, text=c)
        tree.column("Date", width=140)
        tree.column("Pair", width=180)
        tree.column("Severity", width=100)
        tree.column("Details", width=400)
        tree.pack(fill="both", expand=True, padx=20, pady=20)

        for r in rows:
            pair = f"{r['drug_a']} + {r['drug_b']}"
            tree.insert("", tk.END, values=(r['timestamp'], pair, r['severity'], r['summary']))
        
        ttk.Button(win, text="Download PDF Report", style="Primary.TButton", command=lambda: self.generate_pdf(rows)).pack(pady=20, ipady=5)

    def generate_pdf(self, rows):
        if not HAS_REPORTLAB:
            messagebox.showerror("Error", "ReportLab not installed.")
            return
        
        default_name = f"PharmaSense_History_{datetime.now().strftime('%Y-%m-%d')}.pdf"
        f = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], initialfile=default_name)
        
        if f:
            c = canvas.Canvas(f, pagesize=letter)
            y = 750
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "Interaction History Report")
            y -= 30
            c.setFont("Helvetica", 10)
            
            c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 40
            
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, "Date                   | Pair                          | Severity")
            y -= 10
            c.line(50, y, 550, y)
            y -= 20
            
            c.setFont("Helvetica", 10)
            for r in rows:
                if y < 50: c.showPage(); y=750
                line = f"{r['timestamp']} | {r['drug_a']} + {r['drug_b']} | {r['severity']}"
                c.drawString(50, y, line)
                y -= 20
            c.save()
            messagebox.showinfo("Success", "PDF Saved")

if __name__ == "__main__":
    app = PharmaApp()
    app.mainloop()