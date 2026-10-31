# -*- coding: utf-8 -*-
"""
Protect - Proteja suas pastas com senha (criptografia real AES)
Desenvolvedores: WS Dev
"""
import os
import hashlib
import json
import base64
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken

APP_NAME = "Protect"
DEV = "WS Dev"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Protect")
DATA_FILE = os.path.join(DATA_DIR, "protected.json")

AZUL = "#0B3D91"
AZUL_CLARO = "#1565D8"
AMARELO = "#FFC400"
AMARELO_CLARO = "#FFD54F"
FUNDO = "#0A2540"


def derivar_chave(senha: str, salt: bytes) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, 200_000)
    return base64.urlsafe_b64encode(dk)


def hash_senha(senha: str) -> str:
    return hashlib.sha256(("Protect$WSDev$" + senha).encode("utf-8")).hexdigest()


def carregar_dados() -> dict:
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def salvar_dados(dados: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)


def criptografar_pasta(pasta: str, senha: str, info: dict) -> None:
    salt = os.urandom(16)
    fernet = Fernet(derivar_chave(senha, salt))
    arquivos = []
    for raiz, _dirs, nomes in os.walk(pasta):
        for nome in nomes:
            arquivos.append(os.path.join(raiz, nome))
    manifesto = []
    for caminho in arquivos:
        rel = os.path.relpath(caminho, pasta).replace("\\", "/")
        with open(caminho, "rb") as f:
            dados_arq = f.read()
        token = fernet.encrypt(dados_arq)
        manifesto.append({"nome": rel, "dados": base64.b64encode(token).decode("ascii")})
    cofre = {
        "app": APP_NAME,
        "versao": 2,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": hash_senha(senha),
        "arquivos": manifesto,
    }
    destino = pasta + ".pprot"
    with open(destino, "w", encoding="utf-8") as f:
        json.dump(cofre, f)
    info.update({"cofre": destino, "hash": cofre["hash"], "bloqueada": True, "criptografada": True})
    for caminho in arquivos:
        try:
            os.remove(caminho)
        except OSError:
            pass
    _limpar_subpastas(pasta)


def _limpar_subpastas(pasta: str) -> None:
    for raiz, dirs, _nomes in os.walk(pasta, topdown=False):
        for d in dirs:
            try:
                os.rmdir(os.path.join(raiz, d))
            except OSError:
                pass
    try:
        os.rmdir(pasta)
    except OSError:
        pass


def descriptografar_cofre(cofre_path: str, senha: str, destino: str) -> None:
    with open(cofre_path, "r", encoding="utf-8") as f:
        cofre = json.load(f)
    if hash_senha(senha) != cofre.get("hash"):
        raise PermissionError("Senha incorreta")
    salt = base64.b64decode(cofre["salt"])
    fernet = Fernet(derivar_chave(senha, salt))
    os.makedirs(destino, exist_ok=True)
    for item in cofre["arquivos"]:
        token = base64.b64decode(item["dados"])
        try:
            conteudo = fernet.decrypt(token)
        except InvalidToken:
            raise PermissionError("Senha incorreta")
        caminho_final = os.path.join(destino, item["nome"])
        os.makedirs(os.path.dirname(caminho_final) or destino, exist_ok=True)
        with open(caminho_final, "wb") as f:
            f.write(conteudo)


class ProtectApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} - WS Dev")
        self.geometry("620x540")
        self.resizable(False, False)
        self.configure(fg_color=FUNDO)
        self.dados = carregar_dados()
        self.pasta = None
        self._montar_ui()

    def _montar_ui(self):
        topo = ctk.CTkFrame(self, fg_color=AZUL, corner_radius=0)
        topo.pack(fill="x")
        ctk.CTkLabel(topo, text="PROTECT", font=ctk.CTkFont(size=32, weight="bold"),
                     text_color=AMARELO).pack(pady=(18, 2))
        ctk.CTkLabel(topo, text=f"Criptografia de pastas com senha  |  {DEV}",
                     font=ctk.CTkFont(size=13), text_color="#BBD3F0").pack(pady=(0, 14))

        corpo = ctk.CTkFrame(self, fg_color="transparent")
        corpo.pack(fill="both", expand=True, padx=30, pady=16)

        frame_pasta = ctk.CTkFrame(corpo, fg_color=AZUL, corner_radius=14)
        frame_pasta.pack(fill="x")
        ctk.CTkLabel(frame_pasta, text="Pasta selecionada:", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=AMARELO).pack(anchor="w", padx=16, pady=(12, 2))
        self.lbl_pasta = ctk.CTkLabel(frame_pasta, text="Nenhuma pasta selecionada",
                                      font=ctk.CTkFont(size=13), text_color="#DCE8F8",
                                      wraplength=520, anchor="w")
        self.lbl_pasta.pack(anchor="w", padx=16, pady=(0, 6))
        self.btn_escolher = ctk.CTkButton(frame_pasta, text="Escolher Pasta", command=self.escolher_pasta,
                                          fg_color=AMARELO, hover_color=AMARELO_CLARO, text_color="#1A1A1A",
                                          font=ctk.CTkFont(size=14, weight="bold"), height=38, corner_radius=10)
        self.btn_escolher.pack(fill="x", padx=16, pady=(0, 6))
        self.btn_cofre = ctk.CTkButton(frame_pasta, text="Abrir Cofre (.pprot)", command=self.escolher_cofre,
                                       fg_color=AZUL_CLARO, hover_color=AZUL, border_color=AMARELO,
                                       border_width=2, text_color=AMARELO,
                                       font=ctk.CTkFont(size=13, weight="bold"), height=34, corner_radius=10)
        self.btn_cofre.pack(fill="x", padx=16, pady=(0, 14))
        self.cofre_atual = None

        frame_senha = ctk.CTkFrame(corpo, fg_color=AZUL, corner_radius=14)
        frame_senha.pack(fill="x", pady=(12, 0))
        ctk.CTkLabel(frame_senha, text="Senha:", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=AMARELO).pack(anchor="w", padx=16, pady=(12, 2))
        self.entry_senha = tk.Entry(frame_senha, show="*", bg=FUNDO, fg=AMARELO,
                                    insertbackground=AMARELO, relief="flat",
                                    font=("Segoe UI", 14), justify="center")
        self.entry_senha.pack(fill="x", padx=16, pady=(0, 4), ipady=8)
        self.entry_senha.bind("<Return>", lambda e: self.desbloquear())
        self.entry_senha.focus_set()

        frame_botoes = ctk.CTkFrame(corpo, fg_color="transparent")
        frame_botoes.pack(fill="x", pady=(14, 0))
        self.btn_bloquear = ctk.CTkButton(frame_botoes, text="PROTEGER COM SENHA", command=self.bloquear,
                                          fg_color=AZUL_CLARO, hover_color=AZUL, border_color=AMARELO,
                                          border_width=2, font=ctk.CTkFont(size=15, weight="bold"),
                                          height=46, corner_radius=12)
        self.btn_bloquear.pack(side="left", fill="x", expand=True, ipady=2)
        self.btn_desbloquear = ctk.CTkButton(frame_botoes, text="ABRIR COM SENHA", command=self.desbloquear,
                                             fg_color=AMARELO, hover_color=AMARELO_CLARO, text_color="#1A1A1A",
                                             font=ctk.CTkFont(size=15, weight="bold"), height=46, corner_radius=12)
        self.btn_desbloquear.pack(side="left", fill="x", expand=True, ipady=2, padx=(12, 0))

        self.lbl_status = ctk.CTkLabel(corpo, text="", font=ctk.CTkFont(size=13, weight="bold"),
                                       text_color=AMARELO, wraplength=540)
        self.lbl_status.pack(pady=(14, 2))

        frame_lista = ctk.CTkFrame(corpo, fg_color=AZUL, corner_radius=14)
        frame_lista.pack(fill="both", expand=True, pady=(8, 0))
        ctk.CTkLabel(frame_lista, text="Pastas protegidas:", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=AMARELO).pack(anchor="w", padx=16, pady=(8, 2))
        self.txt_lista = ctk.CTkTextbox(frame_lista, fg_color=FUNDO, text_color="#DCE8F8",
                                        font=ctk.CTkFont(size=12), border_color=AZUL_CLARO, border_width=1)
        self.txt_lista.pack(fill="both", expand=True, padx=16, pady=(2, 10))
        self.atualizar_lista()

        ctk.CTkLabel(self, text=f"{APP_NAME} (c) 2026 - {DEV}", font=ctk.CTkFont(size=12),
                     text_color="#7FA6D9").pack(pady=(0, 8))

    def atualizar_lista(self):
        self.txt_lista.configure(state="normal")
        self.txt_lista.delete("1.0", "end")
        if not self.dados:
            self.txt_lista.insert("1.0", "Nenhuma pasta protegida ainda.")
        else:
            for caminho, info in self.dados.items():
                if info.get("criptografada"):
                    estado = "CRIPTOGRAFADA (cofre .pprot)"
                elif info.get("bloqueada"):
                    estado = "protegida"
                else:
                    estado = "aberta"
                self.txt_lista.insert("end", f"{caminho}\n   Estado: {estado}\n\n")
        self.txt_lista.configure(state="disabled")

    def set_status(self, texto):
        self.lbl_status.configure(text=texto)

    def escolher_pasta(self):
        caminho = filedialog.askdirectory(title="Selecione a pasta para proteger")
        if caminho:
            self.pasta = os.path.normpath(caminho)
            self.cofre_atual = None
            self.lbl_pasta.configure(text=self.pasta)
            if self.pasta in self.dados:
                info = self.dados[self.pasta]
                estado = "CRIPTOGRAFADA" if info.get("criptografada") else "aberta"
                self.set_status(f"Pasta já registrada — estado: {estado}")
            else:
                self.set_status("Pasta selecionada. Defina uma senha e clique em PROTEGER COM SENHA.")

    def _validar_selecao(self):
        if not self.pasta:
            messagebox.showwarning(APP_NAME, "Selecione uma pasta primeiro!")
            return False
        return True

    def escolher_cofre(self):
        caminho = filedialog.askopenfilename(
            title="Selecione o cofre .pprot",
            filetypes=[("Cofre Protect", "*.pprot"), ("Todos os arquivos", "*.*")])
        if caminho:
            self.cofre_atual = os.path.normpath(caminho)
            # pasta de destino = nome do cofre sem a extensao .pprot
            self.pasta = self.cofre_atual[:-len(".pprot")] if self.cofre_atual.endswith(".pprot") else self.cofre_atual
            self.lbl_pasta.configure(text=self.pasta)
            self.set_status("Cofre selecionado. Digite a senha e clique em ABRIR COM SENHA.")

    def bloquear(self):
        if not self._validar_selecao():
            return
        senha = self.entry_senha.get()
        if len(senha) < 4:
            messagebox.showwarning(APP_NAME, "A senha deve ter pelo menos 4 caracteres.")
            return
        if not os.path.isdir(self.pasta):
            messagebox.showwarning(APP_NAME, "A pasta não existe (já pode estar criptografada).\n"
                                             "Se existir o arquivo .pprot, use ABRIR COM SENHA.")
            return
        if not messagebox.askyesno(APP_NAME,
                                   "A pasta será CRIPTOGRAFADA (AES + PBKDF2).\n\n"
                                   "Os arquivos originais serão removidos e substituídos por um cofre "
                                   "protegido por senha. Só será possível recuperá-los com a senha.\n\n"
                                   "Continuar?"):
            return
        try:
            info = self.dados.get(self.pasta, {})
            self.dados[self.pasta] = info
            criptografar_pasta(self.pasta, senha, info)
            salvar_dados(self.dados)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Erro ao criptografar:\n{e}")
            return
        self.entry_senha.delete(0, "end")
        self.atualizar_lista()
        self.set_status(f"OK - Pasta criptografada: {self.pasta}.pprot")
        messagebox.showinfo(APP_NAME, "Pasta criptografada com sucesso!\n\n"
                                      f"Cofre criado:\n{self.pasta}.pprot\n\n"
                                      "Para recuperar os arquivos, use ABRIR COM SENHA.")

    def desbloquear(self):
        if not self._validar_selecao():
            return
        senha = self.entry_senha.get()
        cofre = self.cofre_atual if self.cofre_atual and os.path.isfile(self.cofre_atual) else self.pasta + ".pprot"
        if not os.path.isfile(cofre):
            messagebox.showwarning(APP_NAME, "Cofre não encontrado:\n" + cofre +
                                   "\n\nUse o botão ABRIR COFRE (.pprot) para localizá-lo.")
            return
        destino = self.pasta
        try:
            descriptografar_cofre(cofre, senha, destino)
        except PermissionError:
            messagebox.showerror(APP_NAME, "Senha incorreta! Acesso negado.")
            self.set_status("Senha incorreta. Tente novamente.")
            return
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Erro ao descriptografar:\n{e}")
            return
        try:
            os.remove(cofre)
        except OSError:
            pass
        info = self.dados.get(self.pasta, {})
        info["bloqueada"] = False
        info["criptografada"] = False
        info.pop("cofre", None)
        self.dados[self.pasta] = info
        salvar_dados(self.dados)
        self.entry_senha.delete(0, "end")
        self.atualizar_lista()
        self.set_status(f"Senha correta! Pasta restaurada: {destino}")
        messagebox.showinfo(APP_NAME, "Pasta desbloqueada!\n\nOs arquivos foram restaurados e estão acessíveis.\n"
                                      "Use PROTEGER COM SENHA para criptografar novamente.")
        os.startfile(destino)


if __name__ == "__main__":
    app = ProtectApp()
    app.mainloop()
