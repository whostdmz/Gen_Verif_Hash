import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from core.hash_utils import *

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        # configuration de la fenêtre principale
        self.title("Hash Generator")
        self.geometry("900x700")
        self.resizable(False, False)

        # Couleurs du thème d'apres Wada Sanzo, cool pour association des couleurs '
        self.colors = {
            'bg': '#000831',           # Bleu très foncé
            'bg_secondary': '#001044', # Bleu foncé secondaire
            'bg_input': '#001a5c',     # Bleu foncé pour inputs
            'border': '#96bfe6',       # Bleu clair pour bordures
            'text': '#b5d1cc',         # Vert d'eau pour texte
            'text_dim': '#6b8a95',     # Vert d'eau atténué
            'accent': '#96bfe6',       # Bleu clair accent
            'accent_hover': '#7ba5cf', # Bleu clair hover
            'success': '#4ade80',
            'error': '#ef4444'
        }

        self.configure(bg=self.colors['bg'])

        # style personnalisé
        self._setup_styles()

        # Header
        self._create_header()

        # création du Notebook (onglets)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=30, pady=(0, 30))

        # cCréation des onglets
        self._create_text_hash_tab()
        self._create_file_hash_tab()
        self._create_verify_tab()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('default')

        # style du Notebook
        style.configure('TNotebook',
            background=self.colors['bg'],
            borderwidth=0,
            tabmargins=[10, 10, 10, 0]
        )
        style.configure('TNotebook.Tab',
            background=self.colors['bg_secondary'],
            foreground=self.colors['text_dim'],
            padding=[20, 12],
            borderwidth=0,
            font=('Segoe UI', 10)
        )
        style.map('TNotebook.Tab',
            background=[('selected', self.colors['accent'])],
            foreground=[('selected', self.colors['bg'])],
            expand=[('selected', [1, 1, 1, 0])]
        )

        # Style des frames
        style.configure('TFrame', background=self.colors['bg_secondary'])

    def _create_header(self):
        header_frame = tk.Frame(self, bg=self.colors['bg'], height=120)
        header_frame.pack(fill="x", pady=(30, 20))
        header_frame.pack_propagate(False)

        # Icône (cercle avec #)
        icon_canvas = tk.Canvas(
            header_frame,
            width=60,
            height=60,
            bg=self.colors['bg'],
            highlightthickness=0
        )
        icon_canvas.pack(pady=(10, 10))

        # Cercle avec bordure bleu clair
        icon_canvas.create_oval(2, 2, 58, 58, fill=self.colors['bg_secondary'], outline=self.colors['accent'], width=3)
        icon_canvas.create_text(30, 30, text="#", font=('Segoe UI', 24, 'bold'), fill=self.colors['accent'])

        # Titre
        title = tk.Label(
            header_frame,
            text="Hash Generator",
            font=('Segoe UI', 28, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        title.pack()

        # Sous-titre
        subtitle = tk.Label(
            header_frame,
            text="Générez et vérifiez vos hashs de manière sécurisée",
            font=('Segoe UI', 11),
            fg=self.colors['text_dim'],
            bg=self.colors['bg']
        )
        subtitle.pack()

    def _create_text_hash_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📝 Texte")

        # Container principal
        container = tk.Frame(frame, bg=self.colors['bg_secondary'])
        container.pack(expand=True, fill="both", padx=40, pady=30)

        # Label
        label = tk.Label(
            container,
            text="Texte à hasher",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        label.pack(anchor="w", pady=(0, 8))

        # Zone de texte
        text_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        text_frame.pack(fill="x", pady=(0, 20))

        self.text_input = tk.Text(
            text_frame,
            height=6,
            font=('Consolas', 10),
            bg=self.colors['bg_input'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief="flat",
            padx=12,
            pady=12,
            wrap="word"
        )
        self.text_input.pack(fill="both")

        # Algorithme
        algo_label = tk.Label(
            container,
            text="Algorithme",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        algo_label.pack(anchor="w", pady=(0, 8))

        self.algo_combo = ttk.Combobox(
            container,
            values=["bcrypt", "Argon2"],
            state="readonly",
            font=('Segoe UI', 10)
        )
        self.algo_combo.set("bcrypt")
        self.algo_combo.pack(fill="x", pady=(0, 20))

        # Bouton Générer
        generate_btn = tk.Button(
            container,
            text="Générer Hash",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['bg'],
            relief="flat",
            cursor="hand2",
            padx=30,
            pady=12,
            command=self._on_generate_text_hash
        )
        generate_btn.pack(fill="x", pady=(0, 20))
        generate_btn.bind('<Enter>', lambda e: e.widget.config(bg=self.colors['accent_hover']))
        generate_btn.bind('<Leave>', lambda e: e.widget.config(bg=self.colors['accent']))

        # Résultat
        result_label = tk.Label(
            container,
            text="Résultat",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        result_label.pack(anchor="w", pady=(0, 8))

        result_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        result_frame.pack(fill="x")

        self.text_result = tk.Text(
            result_frame,
            height=3,
            font=('Consolas', 9),
            bg=self.colors['bg_input'],
            fg=self.colors['accent'],
            relief="flat",
            padx=12,
            pady=12,
            wrap="word",
            state="disabled"
        )
        self.text_result.pack(fill="both")

    def _create_file_hash_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📁 Fichier")

        container = tk.Frame(frame, bg=self.colors['bg_secondary'])
        container.pack(expand=True, fill="both", padx=40, pady=30)

        # Label
        label = tk.Label(
            container,
            text="Fichier à hasher",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        label.pack(anchor="w", pady=(0, 8))

        # Zone de sélection fichier
        file_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        file_frame.pack(fill="x", pady=(0, 20))

        inner_frame = tk.Frame(file_frame, bg=self.colors['bg_input'])
        inner_frame.pack(fill="both", expand=True, padx=12, pady=40)

        upload_label = tk.Label(
            inner_frame,
            text="📤 Cliquez pour sélectionner un fichier",
            font=('Segoe UI', 11),
            fg=self.colors['text'],
            bg=self.colors['bg_input'],
            cursor="hand2"
        )
        upload_label.pack()
        upload_label.bind('<Button-1>', lambda e: self._on_browse_file())
        upload_label.bind('<Enter>', lambda e: e.widget.config(fg=self.colors['accent']))
        upload_label.bind('<Leave>', lambda e: e.widget.config(fg=self.colors['text']))

        self.file_path_label = tk.Label(
            container,
            text="",
            font=('Segoe UI', 9),
            fg=self.colors['accent'],
            bg=self.colors['bg_secondary']
        )
        self.file_path_label.pack(anchor="w", pady=(0, 20))

        # Algorithme
        algo_label = tk.Label(
            container,
            text="Algorithme",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        algo_label.pack(anchor="w", pady=(0, 8))

        self.file_algo = ttk.Combobox(
            container,
            values=["SHA-256", "SHA-512"],
            state="readonly",
            font=('Segoe UI', 10)
        )
        self.file_algo.set("SHA-256")
        self.file_algo.pack(fill="x", pady=(0, 20))

        # Bouton
        hash_btn = tk.Button(
            container,
            text="Générer Hash",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['bg'],
            relief="flat",
            cursor="hand2",
            padx=30,
            pady=12,
            command=self._on_generate_file_hash
        )
        hash_btn.pack(fill="x", pady=(0, 20))
        hash_btn.bind('<Enter>', lambda e: e.widget.config(bg=self.colors['accent_hover']))
        hash_btn.bind('<Leave>', lambda e: e.widget.config(bg=self.colors['accent']))

        # Résultat
        result_label = tk.Label(
            container,
            text="Résultat",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        result_label.pack(anchor="w", pady=(0, 8))

        result_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        result_frame.pack(fill="x")

        self.file_result = tk.Text(
            result_frame,
            height=3,
            font=('Consolas', 9),
            bg=self.colors['bg_input'],
            fg=self.colors['accent'],
            relief="flat",
            padx=12,
            pady=12,
            wrap="word",
            state="disabled"
        )
        self.file_result.pack(fill="both")

    def _create_verify_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="✓ Vérification")

        container = tk.Frame(frame, bg=self.colors['bg_secondary'])
        container.pack(expand=True, fill="both", padx=40, pady=30)

        # Mot de passe
        pwd_label = tk.Label(
            container,
            text="Mot de passe",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        pwd_label.pack(anchor="w", pady=(0, 8))

        pwd_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        pwd_frame.pack(fill="x", pady=(0, 20))

        self.pw_entry = tk.Entry(
            pwd_frame,
            show="•",
            font=('Segoe UI', 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief="flat"
        )
        self.pw_entry.pack(fill="both", padx=12, pady=12)

        # Hash
        hash_label = tk.Label(
            container,
            text="Hash à comparer",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg_secondary']
        )
        hash_label.pack(anchor="w", pady=(0, 8))

        hash_frame = tk.Frame(container, bg=self.colors['border'], padx=2, pady=2)
        hash_frame.pack(fill="x", pady=(0, 20))

        self.hash_entry = tk.Text(
            hash_frame,
            height=4,
            font=('Consolas', 9),
            bg=self.colors['bg_input'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief="flat",
            padx=12,
            pady=12,
            wrap="word"
        )
        self.hash_entry.pack(fill="both")

        # Bouton Vérifier
        verify_btn = tk.Button(
            container,
            text="Vérifier",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['bg'],
            relief="flat",
            cursor="hand2",
            padx=30,
            pady=12,
            command=self._on_verify_hash
        )
        verify_btn.pack(fill="x", pady=(0, 20))
        verify_btn.bind('<Enter>', lambda e: e.widget.config(bg=self.colors['accent_hover']))
        verify_btn.bind('<Leave>', lambda e: e.widget.config(bg=self.colors['accent']))

        # Label résultat
        result_frame = tk.Frame(container, bg=self.colors['bg_secondary'])
        result_frame.pack(fill="x")

        self.verify_label = tk.Label(
            result_frame,
            text="",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg_secondary'],
            pady=15
        )
        self.verify_label.pack(fill="x")

    def _on_generate_text_hash(self):
        texte = self.text_input.get("1.0", "end-1c").strip()
        algo = self.algo_combo.get()
        if not texte:
            messagebox.showwarning("Attention", "Le texte est vide.")
            return
        result = gen_hash(texte, algo)
        self.text_result.config(state="normal")
        self.text_result.delete("1.0", "end")
        self.text_result.insert("1.0", result)
        self.text_result.config(state="disabled")

    def _on_browse_file(self):
        filename = filedialog.askopenfilename(title="Sélectionner un fichier")
        if filename:
            self.selected_file = filename
            self.file_path_label.config(text=f"📄 {filename.split('/')[-1]}")

    def _on_generate_file_hash(self):
        if not hasattr(self, 'selected_file') or not self.selected_file:
            messagebox.showwarning("Attention", "Aucun fichier sélectionné.")
            return

        result = hash_file(self.selected_file, size=65536)
        self.file_result.config(state="normal")
        self.file_result.delete("1.0", "end")
        self.file_result.insert("1.0", result)
        self.file_result.config(state="disabled")

    def _on_verify_hash(self):
        pwd = self.pw_entry.get().strip()
        hsh = self.hash_entry.get("1.0", "end-1c").strip()
        if not pwd or not hsh:
            messagebox.showwarning("Attention", "Champs incomplets.")
            return
        valid = verif_hash(pwd, hsh)
        if valid:
            self.verify_label.config(
                text="✓ Hash valide",
                fg=self.colors['success']
            )
        else:
            self.verify_label.config(
                text="✗ Hash invalide",
                fg=self.colors['error']
            )

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
