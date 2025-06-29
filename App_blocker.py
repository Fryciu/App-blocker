import os
import psutil
import tkinter as tk
from tkinter import simpledialog, messagebox, Listbox, Button, END
import json
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from datetime import datetime
from pathlib import Path


boot_time = psutil.boot_time()
boot_time_dt = datetime.fromtimestamp(boot_time)
now = datetime.now()
current_path = Path(__file__).parent


# Konfiguracja szyfrowania
KEY = b"Thisisa32bytesecret-key-for-AES!" # KLUCZ AES: Musi mieć dokładnie 16, 24 lub 32 bajty.
                                       # Ten klucz MUSI pozostać stały. Służy do szyfrowania danych.
CONFIG_FILE = "blocked_apps.enc"       # Nazwa zaszyfrowanego pliku konfiguracyjnego aplikacji
PASSWORD_FILE = "password.enc"         # Nazwa zaszyfrowanego pliku z hasłem

# Szyfrowanie danych JSON za pomocą AES
def encrypt_data(data):
    """
    Szyfruje dowolne dane (konwertowane na string JSON) za pomocą AES w trybie CBC.
    Dane są dopełniane, a następnie szyfrowane.
    IV (Initialization Vector) i szyfrogram są kodowane do Base64 dla bezpiecznego przechowywania.
    """
    json_data_bytes = json.dumps(data).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(json_data_bytes, AES.block_size))
    encrypted_payload = {
        "iv": base64.b64encode(cipher.iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ct_bytes).decode('utf-8')
    }
    return encrypted_payload

# Deszyfrowanie zaszyfrowanych danych JSON
def decrypt_data(encrypted_payload):
    """
    Deszyfruje zaszyfrowane dane (w formacie JSON, Base64).
    IV i szyfrogram są dekodowane z Base64, następnie dane są deszyfrowane i parsowane z JSON.
    """
    iv = base64.b64decode(encrypted_payload["iv"])
    ct = base64.b64decode(encrypted_payload["ciphertext"])
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    decrypted_bytes = unpad(cipher.decrypt(ct), AES.block_size)
    decrypted_data_str = decrypted_bytes.decode('utf-8')
    return json.loads(decrypted_data_str)

# --- Zarządzanie hasłem ---

def load_password():
    """
    Ładuje zaszyfrowane hasło z pliku PASSWORD_FILE.
    Jeśli plik nie istnieje lub jest uszkodzony, inicjalizuje go domyślnym hasłem i zapisuje.
    """
    if os.path.exists(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, "r") as f:
                content = json.load(f)
                return decrypt_data(content)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            messagebox.showerror("Błąd pliku hasła", 
                                 f"Wystąpił błąd podczas ładowania lub deszyfrowania pliku hasła '{PASSWORD_FILE}': {e}\n"
                                 "Plik mógł być uszkodzony. Inicjalizuję domyślne hasło '1234'.")
            default_password = "1234"
            save_password(default_password) # Zapisz domyślne hasło
            return default_password
        except Exception as e:
            messagebox.showerror("Błąd ładowania hasła", f"Nieoczekiwany błąd podczas ładowania hasła: {e}\n"
                                 "Inicjalizuję domyślne hasło '1234'.")
            default_password = "1234"
            save_password(default_password)
            return default_password
    else:
        # Jeśli plik hasła nie istnieje, utwórz go z domyślnym hasłem
        messagebox.showinfo("Pierwsze uruchomienie", 
                            "Plik hasła nie został znaleziony. Zostanie utworzony z domyślnym hasłem '1234'. "
                            "Zaleca się jego zmianę w Menedżerze Konfiguracji.")
        default_password = "1234"
        save_password(default_password)
        return default_password

def save_password(new_password):
    """
    Szyfruje i zapisuje nowe hasło do pliku PASSWORD_FILE.
    """
    try:
        with open(PASSWORD_FILE, "w") as f:
            encrypted_password = encrypt_data(new_password)
            json.dump(encrypted_password, f, indent=4)
        messagebox.showinfo("Sukces", "Hasło zostało pomyślnie zmienione.")
    except Exception as e:
        messagebox.showerror("Błąd zapisu hasła", f"Nie udało się zapisać hasła: {e}")

# Sprawdź hasło użytkownika
def check_password():
    """
    Prosi użytkownika o hasło za pomocą okna dialogowego Tkinter i sprawdza je
    względem hasła załadowanego z pliku.
    """
    root = tk.Tk()
    root.withdraw()
    current_stored_password = load_password() # Załaduj aktualne hasło z pliku
    password_input = simpledialog.askstring("Wymagane hasło", "Podaj hasło (po inicjalizacji domyślne hasło '1234'):", show='*')
    root.destroy()
    return password_input == current_stored_password

# --- Zarządzanie listą aplikacji ---

def load_blocked_apps():
    """
    Ładuje zaszyfrowaną listę zablokowanych aplikacji z pliku konfiguracyjnego.
    W przypadku braku pliku lub błędów deszyfrowania, zwraca pustą listę i informuje użytkownika.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                content = json.load(f)
                return decrypt_data(content)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            messagebox.showerror("Błąd pliku konfiguracyjnego", 
                                 f"Wystąpił błąd podczas ładowania lub deszyfrowania pliku '{CONFIG_FILE}': {e}\n"
                                 "Plik mógł być uszkodzony. Tworzę nową, pustą konfigurację.")
            return []
        except Exception as e:
            messagebox.showerror("Błąd ładowania", f"Nieoczekiwany błąd podczas ładowania zablokowanych aplikacji: {e}\n"
                                 "Tworzę nową, pustą konfigurację.")
            return []
    return []

def save_blocked_apps(apps):
    """
    Zapisuje listę zablokowanych aplikacji do zaszyfrowanego pliku konfiguracyjnego.
    """
    try:
        with open(CONFIG_FILE, "w") as f:
            encrypted_data = encrypt_data(apps)
            json.dump(encrypted_data, f, indent=4)
    except Exception as e:
        messagebox.showerror("Błąd zapisu", f"Nie udało się zapisać zablokowanych aplikacji: {e}")

# --- Tryby działania aplikacji ---
    
def block_mode():
    """
    Monitoruje uruchomione procesy i zamyka te, które znajdują się na czarnej liście.
    """
    print("--------------------------------------------------")
    print("TRYB BLOKUJĄCY AKTYWNY: Aplikacje na czarnej liście będą zamykane.")
    print("Aby zatrzymać, zamknij to okno konsoli lub proces.")
    print("--------------------------------------------------")
    
    while True:
        blocked_apps_current = load_blocked_apps()
        blocked_apps_current_lower = [app.lower() for app in blocked_apps_current]

        for proc in psutil.process_iter(['name']):
            try:
                process_name = proc.info['name'].lower()
                if process_name in blocked_apps_current_lower:
                    print(f"Zabijam proces: {proc.info['name']} (PID: {proc.pid})")
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception as e:
                print(f"Błąd podczas przetwarzania procesu {proc.info['name']}: {e}")
        time.sleep(1)
    

def config_mode():
    """
    Zarządza listą zablokowanych aplikacji za pomocą graficznego interfejsu użytkownika (GUI)
    oraz umożliwia zmianę hasła.
    """
    if not check_password():
        messagebox.showerror("Błąd autoryzacji", "Nieprawidłowe hasło! Nie można uruchomić trybu konfiguracyjnego.")
        return

    blocked_apps = load_blocked_apps()
    
    root = tk.Tk()
    root.title("Menedżer Blokady Aplikacji")
    root.geometry("400x520") # Zwiększono wysokość, aby pomieścić nowy przycisk
    root.resizable(False, False)

    title_label = tk.Label(root, text="Zablokowane Aplikacje", font=("Helvetica", 16, "bold"), fg="#333")
    title_label.pack(pady=10)

    list_frame = tk.Frame(root, bd=2, relief="sunken")
    list_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    listbox = Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode=tk.MULTIPLE,
                      font=("Helvetica", 12), bd=0, highlightthickness=0, selectbackground="#a6d5ff", selectforeground="black")
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    def refresh_listbox():
        listbox.delete(0, END)
        sorted_apps = sorted(blocked_apps)
        for app in sorted_apps:
            listbox.insert(END, app)

    refresh_listbox()
    
    def add_app():
        app = simpledialog.askstring("Dodaj Aplikację", "Podaj pełną nazwę pliku .exe (np. chrome.exe, notepad.exe):")
        if app:
            app_lower = app.lower().strip()
            if app_lower and app_lower not in blocked_apps:
                blocked_apps.append(app_lower)
                save_blocked_apps(blocked_apps)
                refresh_listbox()
                messagebox.showinfo("Sukces", f"Aplikacja '{app}' została dodana do listy blokady.")
            elif app_lower:
                messagebox.showinfo("Informacja", f"Aplikacja '{app}' jest już na liście blokady.")
    
    def remove_app():
        selected_indices = listbox.curselection()
        if selected_indices:
            items_to_remove = [listbox.get(i) for i in selected_indices]
            for item in items_to_remove:
                if item in blocked_apps:
                    blocked_apps.remove(item)
            
            save_blocked_apps(blocked_apps)
            refresh_listbox()
            messagebox.showinfo("Sukces", "Wybrane aplikacje zostały usunięte z listy blokady.")
        else:
            messagebox.showinfo("Informacja", "Wybierz jedną lub więcej aplikacji do usunięcia z listy.")

    def change_password_gui():
        """Obsługuje proces zmiany hasła w GUI."""
        current_password = load_password() # Pobierz aktualne hasło z pliku

        # 1. Poproś o bieżące hasło
        root_temp = tk.Tk()
        root_temp.withdraw()
        old_password_input = simpledialog.askstring("Zmień Hasło", "Podaj obecne hasło:", show='*')
        root_temp.destroy()

        if old_password_input != current_password:
            messagebox.showerror("Błąd", "Nieprawidłowe obecne hasło.")
            return

        # 2. Poproś o nowe hasło
        root_temp = tk.Tk()
        root_temp.withdraw()
        new_password1 = simpledialog.askstring("Zmień Hasło", "Podaj nowe hasło:", show='*')
        root_temp.destroy()

        if not new_password1: # Użytkownik anulował lub nie wpisał nic
            return

        # 3. Poproś o potwierdzenie nowego hasła
        root_temp = tk.Tk()
        root_temp.withdraw()
        new_password2 = simpledialog.askstring("Zmień Hasło", "Potwierdź nowe hasło:", show='*')
        root_temp.destroy()

        if new_password1 == new_password2:
            save_password(new_password1) # Zapisz nowe hasło
        else:
            messagebox.showerror("Błąd", "Nowe hasła nie są identyczne. Spróbuj ponownie.")
    
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    Button(button_frame, text="Dodaj Aplikację", command=add_app, font=("Helvetica", 10), width=18,
           bg="#4CAF50", fg="white", activebackground="#45a049").pack(side=tk.LEFT, padx=8)
    Button(button_frame, text="Usuń Wybraną", command=remove_app, font=("Helvetica", 10), width=18,
           bg="#f44336", fg="white", activebackground="#da190b").pack(side=tk.LEFT, padx=8)
    
    # Nowy przycisk do zmiany hasła
    Button(root, text="Zmień Hasło", command=change_password_gui, font=("Helvetica", 10, "bold"), width=38,
           bg="#FFC107", fg="black", activebackground="#FFD700").pack(pady=10) # Żółty kolor dla wyróżnienia

    close_button = Button(root, text="Zamknij Menedżer", command=root.destroy, font=("Helvetica", 10, "bold"), 
                          bg="#607D8B", fg="white", activebackground="#546E7A")
    close_button.pack(pady=15)
    
    root.mainloop()

def start_gui():
    """
    Wyświetla okno GUI, aby użytkownik mógł wybrać tryb działania aplikacji.
    """
    root = tk.Tk()
    root.title("Wybierz Tryb")
    root.geometry("300x150")
    root.resizable(False, False)
    root.eval('tk::PlaceWindow . center')
    try:
        root.iconbitmap("icon.ico") # Zakładamy, że my_icon.ico jest w tym samym katalogu
    except tk.TclError:
        print("Nie znaleziono pliku ikony 'my_icon.ico' lub wystąpił błąd.")
        # Opcjonalnie: można ustawić domyślną ikonę lub zignorować
        pass

    label = tk.Label(root, text="Wybierz tryb działania aplikacji:", font=("Helvetica", 12, "bold"))
    label.pack(pady=15)

    def on_block_mode():
        root.destroy()
        block_mode()

    def on_config_mode():
        root.destroy()
        config_mode()

    block_button = Button(root, text="Tryb Blokujący", command=on_block_mode, font=("Helvetica", 10), width=15,
                          bg="#007bff", fg="white", activebackground="#0056b3")
    block_button.pack(side=tk.LEFT, padx=10)

    config_button = Button(root, text="Menedżer Konfiguracji", command=on_config_mode, font=("Helvetica", 10), width=20,
                           bg="#28a745", fg="white", activebackground="#218838")
    config_button.pack(side=tk.RIGHT, padx=10)

    root.mainloop()


if __name__ == "__main__":
    # Jeśli skrypt uruchomiono z argumentem do cichej blokady, wykonaj ją.
    
    data_login_path = current_path/"data_login.txt"
    date_string = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")  # Format YYYY-MM-DD HH:MM:SS
    print(type(date_string))
    try:
        print(boot_time_dt)
        print(datetime.now())
        datetxt = open(data_login_path).read().strip()
        date = datetime.strptime(datetxt, "%Y-%m-%d %H:%M:%S.%f")
        if date < boot_time_dt:
            with open(data_login_path, "w") as f:
                f.write(date_string)
            block_mode()
        else:
            start_gui()

    except Exception as e:
        with open(data_login_path, "w") as f:
            f.write(date_string)
            
        block_mode()
    
