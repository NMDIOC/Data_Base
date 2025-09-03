import streamlit as st
import hashlib
import json
import os

# ========= Configuración ========= #
DB_FILE = "usuarios.json"

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Usuario administrador
USERS = {
    "admin": hash_password("admin")
}

# ========= Funciones de base de datos ========= #
def cargar_datos():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            datos = json.load(f)

            # ✅ Normalizar datos a {usuario: {"tokens": int}}
            if isinstance(datos, dict):
                for u, v in list(datos.items()):
                    if isinstance(v, int):
                        datos[u] = {"tokens": v}
            else:
                # si fuera lista u otro formato → convertir
                datos = {}
            return datos
    return {}

def guardar_datos(datos):
    with open(DB_FILE, "w") as f:
        json.dump(datos, f, indent=4)

# ========= Inicializar estado ========= #
if "usuarios" not in st.session_state:
    st.session_state["usuarios"] = cargar_datos()
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None

# ========= Login ========= #
def login():
    st.subheader("🔑 Iniciar Sesión (Admin)")
    username = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")
    if st.button("Iniciar Sesión"):
        if username in USERS and USERS[username] == hash_password(password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.success(f"Bienvenido, {username}")
            st.rerun()
        else:
            st.error("❌ Usuario o contraseña incorrectos")

# ========= Logout ========= #
def logout():
    if st.button("Cerrar Sesión"):
        st.session_state["logged_in"] = False
        st.session_state["username"] = None
        st.rerun()

# ========= App ========= #
st.title("👥 Sistema de Usuarios y Tokens")

# Modo administrador
if st.session_state["logged_in"]:
    st.subheader("👑 Panel de Administración")

    # Mostrar usuarios
    st.write("📋 Lista de usuarios:")
    st.table([{"Usuario": u, "Tokens": d["tokens"]} for u, d in st.session_state["usuarios"].items()])

    # Añadir usuario
    st.divider()
    st.subheader("➕ Añadir usuario")
    nuevo_usuario = st.text_input("Nombre de usuario")
    if st.button("Añadir usuario"):
        if nuevo_usuario and nuevo_usuario not in st.session_state["usuarios"]:
            st.session_state["usuarios"][nuevo_usuario] = {"tokens": 0}
            guardar_datos(st.session_state["usuarios"])
            st.success(f"Usuario {nuevo_usuario} añadido con 0 tokens")
            st.rerun()
        else:
            st.error("❌ Usuario vacío o ya existente")

    # Editar tokens
    st.divider()
    st.subheader("🎯 Editar tokens")
    if st.session_state["usuarios"]:
        usuario_sel = st.selectbox("Selecciona usuario", list(st.session_state["usuarios"].keys()))
        cambio = st.number_input("Cambiar tokens (puede ser negativo)", step=1)
        if st.button("Aplicar cambio"):
            st.session_state["usuarios"][usuario_sel]["tokens"] += cambio
            guardar_datos(st.session_state["usuarios"])
            st.success(f"Tokens de {usuario_sel} actualizados")
            st.rerun()
    else:
        st.info("⚠️ No hay usuarios registrados")

    # Eliminar usuario
    st.divider()
    st.subheader("🗑️ Eliminar usuario")
    if st.session_state["usuarios"]:
        usuario_del = st.selectbox("Selecciona usuario a eliminar", list(st.session_state["usuarios"].keys()))
        if st.button("Eliminar usuario"):
            del st.session_state["usuarios"][usuario_del]
            guardar_datos(st.session_state["usuarios"])
            st.success(f"Usuario {usuario_del} eliminado")
            st.rerun()
    else:
        st.info("⚠️ No hay usuarios para eliminar")

    logout()

# Modo usuario normal (sin login)
else:
    st.subheader("📊 Ranking de Usuarios y Tokens")
    if st.session_state["usuarios"]:
        usuarios_ordenados = sorted(
            st.session_state["usuarios"].items(),
            key=lambda x: x[1]["tokens"],
            reverse=True
        )
        for usuario, datos in usuarios_ordenados:
            st.markdown(f"**👤 {usuario}** — 🎟️ {datos['tokens']} tokens")
    else:
        st.info("⚠️ Aún no hay usuarios registrados")

    st.divider()
    login()
