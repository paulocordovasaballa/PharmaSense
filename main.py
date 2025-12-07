import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import database
import itertools
from datetime import datetime
import threading

# --- 1. IMPORT MODULES ---
try:
    from api_checker import DDInterChecker
except ImportError:
    class DDInterChecker:
        def __init__(self): self.all_drugs = ["Aspirin", "Warfarin", "Ibuprofen"]
        def get_drug_list(self): return self.all_drugs
        def check_interaction(self, d1, d2): return []

try:
    from external_apis import MedicalAPI
except ImportError:
    MedicalAPI = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# --- 2. CONFIGURATION ---
APP_TITLE = "PharmaSense"
WINDOW_SIZE = "1000x700"
FONT_MAIN = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_MONO = ("Consolas", 10)

class PharmaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(900, 600)
        
        # --- STYLING ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#f5f5f5")
        style.configure("TLabel", background="#f5f5f5", font=FONT_MAIN)
        style.configure("TButton", font=FONT_MAIN, padding=6)
        style.configure("Card.TFrame", background="white", relief="solid", borderwidth=1)
        style.configure("Card.TLabel", background="white", font=FONT_MAIN)
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), background="#f5f5f5")

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
        
        card = ttk.Frame(self, style="Card.TFrame", padding=40)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(card, text="PharmaSense", font=FONT_TITLE, style="Card.TLabel").pack(pady=(0, 10))
        ttk.Label(card, text="Clinical Decision Support", style="Card.TLabel").pack(pady=(0, 30))

        ttk.Label(card, text="Username", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.user_entry = ttk.Entry(card, width=35, font=FONT_MAIN)
        self.user_entry.pack(pady=5)

        ttk.Label(card, text="Password", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w", pady=(15, 0))
        self.pass_entry = ttk.Entry(card, show="*", width=35, font=FONT_MAIN)
        self.pass_entry.pack(pady=5)

        ttk.Button(card, text="Log In", command=self.handle_login).pack(fill="x", pady=20)
        
        reg_btn = ttk.Label(card, text="Create New Account", foreground="blue", cursor="hand2", style="Card.TLabel")
        reg_btn.pack()
        reg_btn.bind("<Button-1>", lambda e: controller.show_frame("SignUpPage"))

    def handle_login(self):
        u = self.user_entry.get()
        p = self.pass_entry.get()
        uid = database.authenticate_user(self.controller.conn, u, p)
        if uid:
            self.user_entry.delete(0, tk.END)
            self.pass_entry.delete(0, tk.END)
            self.controller.login_success(uid)
        else:
            messagebox.showerror("Error", "Invalid Credentials")


class SignUpPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        card = ttk.Frame(self, style="Card.TFrame", padding=40)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(card, text="Create Account", font=FONT_TITLE, style="Card.TLabel").pack(pady=(0, 20))

        ttk.Label(card, text="New Username", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w")
        self.user_entry = ttk.Entry(card, width=35, font=FONT_MAIN)
        self.user_entry.pack(pady=5)

        ttk.Label(card, text="New Password", style="Card.TLabel", font=FONT_BOLD).pack(anchor="w", pady=(10, 0))
        self.pass_entry = ttk.Entry(card, show="*", width=35, font=FONT_MAIN)
        self.pass_entry.pack(pady=5)

        ttk.Button(card, text="Sign Up", command=self.handle_signup).pack(fill="x", pady=20)
        
        back_btn = ttk.Label(card, text="Back to Login", foreground="blue", cursor="hand2", style="Card.TLabel")
        back_btn.pack()
        back_btn.bind("<Button-1>", lambda e: controller.show_frame("LoginPage"))

    def handle_signup(self):
        if database.register_user(self.controller.conn, self.user_entry.get(), self.pass_entry.get()):
            messagebox.showinfo("Success", "Account Created")
            self.controller.show_frame("LoginPage")
        else:
            messagebox.showerror("Error", "Username Taken")


class DashboardPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_drugs = []
        self.all_options = []

        # --- Top Header ---
        header = ttk.Frame(self, padding=(20, 10))
        header.pack(fill="x")
        
        ttk.Label(header, text="PharmaSense Dashboard", font=("Segoe UI", 16, "bold")).pack(side="left")
        
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="History Log", command=self.open_history).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Logout", command=controller.logout).pack(side="left", padx=5)

        # --- Main Layout ---
        main_content = ttk.Frame(self, padding=20)
        main_content.pack(fill="both", expand=True)
        main_content.columnconfigure(1, weight=1)
        main_content.rowconfigure(0, weight=1)

        # --- Sidebar (Left) ---
        sidebar = ttk.Frame(main_content, width=300, padding=(0, 0, 20, 0))
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.pack_propagate(False) 

        ttk.Label(sidebar, text="Add Medication", style="Header.TLabel").pack(anchor="w", pady=(0, 10))
        
        ttk.Label(sidebar, text="Search Drug Name:", font=FONT_BOLD).pack(anchor="w")
        self.combo = ttk.Combobox(sidebar, font=FONT_MAIN)
        self.combo.pack(fill="x", pady=5)
        self.combo.bind('<KeyRelease>', self.filter_drugs)

        btn_row = ttk.Frame(sidebar)
        btn_row.pack(fill="x", pady=5)
        ttk.Button(btn_row, text="Add to List", command=self.add_drug).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(btn_row, text="Clear All", command=self.reset_ui).pack(side="left", fill="x", expand=True)

        ttk.Label(sidebar, text="Current Prescriptions:", font=FONT_BOLD).pack(anchor="w", pady=(20, 5))
        
        list_frame = ttk.Frame(sidebar, style="Card.TFrame")
        list_frame.pack(fill="both", expand=True)
        
        self.listbox = tk.Listbox(list_frame, font=FONT_MAIN, borderwidth=0, highlightthickness=0, bg="white")
        self.listbox.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Button(sidebar, text="Run Safety Check", command=self.start_analysis_thread).pack(fill="x", pady=20)


        # --- Results (Right) ---
        results_area = ttk.Frame(main_content)
        results_area.grid(row=0, column=1, sticky="nsew")

        ttk.Label(results_area, text="Analysis Report", style="Header.TLabel").pack(anchor="w", pady=(0, 10))

        report_frame = ttk.Frame(results_area, style="Card.TFrame")
        report_frame.pack(fill="both", expand=True)

        self.report = tk.Text(
            report_frame, 
            font=FONT_MONO, 
            borderwidth=0, 
            highlightthickness=0, 
            padx=15, 
            pady=15,
            wrap="word",     # Correct wrapping
            state="disabled" # Read-only mode
        )
        self.report.pack(fill="both", expand=True)

        self.report.tag_config("FDA", foreground="#6A1B9A", font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self.report.tag_config("MAJOR", foreground="#D32F2F", font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self.report.tag_config("SAFE", foreground="#388E3C", font=(FONT_MONO[0], FONT_MONO[1], "bold"))

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
            self.listbox.insert(tk.END, f"  {val}")
            self.combo.set('')
            self.combo['values'] = self.all_options

    def reset_ui(self):
        self.selected_drugs = []
        self.listbox.delete(0, tk.END)
        # Unlock, clear, then lock again
        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        self.report.config(state="disabled")

    def start_analysis_thread(self):
        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        
        if len(self.selected_drugs) < 2:
            self.report.insert(tk.END, "Please add at least 2 drugs to the list.")
            self.report.config(state="disabled")
            return
            
        self.report.insert(tk.END, "Processing...\n")
        self.report.config(state="disabled")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        # 1. Check FDA
        fda_notes = []
        if self.controller.med_api:
            for drug in self.selected_drugs:
                w = self.controller.med_api.get_fda_warnings(drug)
                if w: fda_notes.append(f"📢 {drug}: {w}")

        # 2. Check Interactions
        interaction_notes = []
        has_interaction = False
        
        # Prepare log data to be saved on main thread
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
                    # LOG SAFE INTERACTIONS
                    logs_to_save.append((d1, d2, "Safe", "No interactions detected", ts))

        # 3. Update UI and DB on Main Thread
        self.after(0, lambda: self.display_results(fda_notes, interaction_notes, has_interaction, logs_to_save))

    def display_results(self, fda_notes, interaction_notes, has_interaction, logs_to_save):
        # Save logs first
        for item in logs_to_save:
            try:
                database.log_interaction(self.controller.conn, self.controller.current_user_id, item[0], item[1], item[2], item[3], item[4])
            except Exception as e:
                print(f"Log Error: {e}")

        # Unlock to display results
        self.report.config(state="normal")
        self.report.delete(1.0, tk.END)
        
        if fda_notes:
            self.report.insert(tk.END, "OFFICIAL FDA WARNINGS\n", "FDA")
            self.report.insert(tk.END, "="*40 + "\n")
            for n in fda_notes: self.report.insert(tk.END, n + "\n\n")
        
        if len(self.selected_drugs) < 2:
             self.report.insert(tk.END, "\nAdd more drugs to check for interactions.")
             self.report.config(state="disabled")
             return

        if has_interaction:
            self.report.insert(tk.END, "\nINTERACTIONS DETECTED\n", "MAJOR")
            self.report.insert(tk.END, "="*40 + "\n")
            for d1, d2, sev, desc in interaction_notes:
                self.report.insert(tk.END, f"⚠ {d1} + {d2}\n", "MAJOR")
                self.report.insert(tk.END, f"Severity: {sev}\nDetails: {desc}\n\n")
        else:
            self.report.insert(tk.END, "\n✅ No interactions found in local database.", "SAFE")
        
        # Lock finally
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
        win.geometry("800x600")

        cols = ("Date", "Pair", "Severity", "Details")
        tree = ttk.Treeview(win, columns=cols, show='headings')
        for c in cols: tree.heading(c, text=c)
        tree.column("Date", width=120)
        tree.column("Pair", width=150)
        tree.column("Severity", width=100)
        tree.column("Details", width=300)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        for r in rows:
            pair = f"{r['drug_a']} + {r['drug_b']}"
            tree.insert("", tk.END, values=(r['timestamp'], pair, r['severity'], r['summary']))
        
        ttk.Button(win, text="Download PDF", command=lambda: self.generate_pdf(rows)).pack(pady=10)

    def generate_pdf(self, rows):
        if not HAS_REPORTLAB:
            messagebox.showerror("Error", "ReportLab not installed.")
            return
        
        # FEATURE: Smart Filename
        default_name = f"PharmaSense_History_{datetime.now().strftime('%Y-%m-%d')}.pdf"
        
        f = filedialog.asksaveasfilename(
            defaultextension=".pdf", 
            filetypes=[("PDF", "*.pdf")],
            initialfile=default_name # Auto-fills the name
        )
        
        if f:
            c = canvas.Canvas(f, pagesize=letter)
            y = 750
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "Interaction History Report")
            y -= 30
            c.setFont("Helvetica", 10)
            
            c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 30
            
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