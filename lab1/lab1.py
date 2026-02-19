import tkinter as tk
from tkinter import filedialog, messagebox
import math

# ===================== АЛФАВИТЫ =====================

ENG_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
RUS_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

# ===================== ДЕЦИМАЦИЙ =====================

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def decimation_encrypt(text, key):
    m = len(ENG_ALPHABET)

    if math.gcd(key, m) != 1:
        messagebox.showerror("Ошибка", "Ключ должен быть взаимно прост с 26.")
        return ""

    result = ""

    for char in text:
        upper_char = char.upper()
        if upper_char in ENG_ALPHABET:
            index = ENG_ALPHABET.index(upper_char)
            new_index = (index * key) % m
            new_char = ENG_ALPHABET[new_index]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char

    return result


def decimation_decrypt(text, key):
    m = len(ENG_ALPHABET)
    inverse_key = mod_inverse(key, m)

    if inverse_key is None:
        messagebox.showerror("Ошибка", "Обратного ключа не существует.")
        return ""

    result = ""

    for char in text:
        upper_char = char.upper()
        if upper_char in ENG_ALPHABET:
            index = ENG_ALPHABET.index(upper_char)
            new_index = (index * inverse_key) % m
            new_char = ENG_ALPHABET[new_index]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char

    return result


# ===================== ВИЖЕНЕР =====================

def is_valid_russian_key(key):
    for char in key.upper():
        if char not in RUS_ALPHABET:
            return False
    return True

def extract_russian(text):
    russian_letters = set(RUS_ALPHABET + RUS_ALPHABET.lower())
    return ''.join(char for char in text if char in russian_letters)


def vigenere_encrypt(text, key):
    m = len(RUS_ALPHABET)
    key = key.upper()
    result = ""
    key_index = 0

    for char in text:
        upper_char = char.upper()

        if upper_char in RUS_ALPHABET:
            text_index = RUS_ALPHABET.index(upper_char)
            key_char = key[key_index % len(key)]
            key_index_value = RUS_ALPHABET.index(key_char)

            new_index = (text_index + key_index_value) % m
            new_char = RUS_ALPHABET[new_index]

            result += new_char.lower() if char.islower() else new_char
            key_index += 1
        else:
            result += char

    return result


def vigenere_decrypt(text, key):
    m = len(RUS_ALPHABET)
    key = key.upper()
    result = ""
    key_index = 0

    for char in text:
        upper_char = char.upper()

        if upper_char in RUS_ALPHABET:
            text_index = RUS_ALPHABET.index(upper_char)
            key_char = key[key_index % len(key)]
            key_index_value = RUS_ALPHABET.index(key_char)

            new_index = (text_index - key_index_value) % m
            new_char = RUS_ALPHABET[new_index]

            result += new_char.lower() if char.islower() else new_char
            key_index += 1
        else:
            result += char

    return result


def extract_digits(text):
    return ''.join(char for char in text if char.isdigit())

# ===================== GUI =====================

class CipherApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Шифратор")
        self.root.geometry("450x420")

        self.algorithm = tk.StringVar(value="decimation")

        tk.Label(root, text="Ключ:").pack(pady=3)
        self.key_entry = tk.Entry(root, width=25)
        self.key_entry.pack()

        tk.Button(root, text="Прочитать из файла", command=self.load_file).pack(pady=3)

        tk.Label(root, text="Исходный текст:").pack()
        self.input_text = tk.Text(root, height=5, width=50)
        self.input_text.pack(padx=5, pady=3)

        tk.Label(root, text="Результирующий текст:").pack()
        self.output_text = tk.Text(root, height=5, width=50)
        self.output_text.pack(padx=5, pady=3)

        frame = tk.Frame(root)
        frame.pack(pady=5)

        tk.Radiobutton(frame,
                       text="Метод децимаций (английский)",
                       variable=self.algorithm,
                       value="decimation").pack()

        tk.Radiobutton(frame,
                       text="Виженер (русский)",
                       variable=self.algorithm,
                       value="vigenere").pack()

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="ШИФРОВАТЬ", command=self.encrypt).pack(side="left", padx=3)
        tk.Button(btn_frame, text="ДЕШИФРОВАТЬ", command=self.decrypt).pack(side="left", padx=3)
        tk.Button(btn_frame, text="ОЧИСТИТЬ", command=self.clear).pack(side="left", padx=3)
        tk.Button(btn_frame, text="Сохранить в файл", command=self.save_file).pack(side="left", padx=3)

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(tk.END, f.read())

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.output_text.get(1.0, tk.END))

    def encrypt(self):
        text = self.input_text.get(1.0, tk.END)
        key = self.key_entry.get()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ.")
            return

        if self.algorithm.get() == "decimation":
            if not extract_digits(key):
                messagebox.showerror("Ошибка", "Ключ должен быть числом.")
                return
            result = decimation_encrypt(text, int(extract_digits(key)))
        else:
            if not extract_russian(key):
                messagebox.showerror("Ошибка", "Ключ должен содержать русские буквы.")
                return
            result = vigenere_encrypt(text,extract_russian(key))

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)

    def decrypt(self):
        text = self.input_text.get(1.0, tk.END)
        key = self.key_entry.get()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ.")
            return

        if self.algorithm.get() == "decimation":
            if not extract_digits(key):
                messagebox.showerror("Ошибка", "Ключ должен быть числом.")
                return
            result = decimation_decrypt(text, int(extract_digits(key)))
        else:
            if not extract_russian(key):
                messagebox.showerror("Ошибка", "Ключ должен содержать русские буквы.")
                return
            result = vigenere_decrypt(text, extract_russian(key))

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)

    def clear(self):
        self.input_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.key_entry.delete(0, tk.END)



root = tk.Tk()
app = CipherApp(root)
root.mainloop()
