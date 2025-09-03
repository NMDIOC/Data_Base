import streamlit as st
import hashlib
import json
import os

# ========= Configuración ========= #
DB_FILE = "usuarios.json"

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ========= Funciones de base de datos ========= #
def cargar_datos():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            datos = json.load(f)

            # Inicializar estructura si no existe
            if "usuarios" not in datos:
                datos["usuarios"] = {}
            if "admin" not in datos:
                datos["admin"] = {"username": "admin", "password": hash_password("admin")}

            # Normalizar usuarios
            for u, v in list(datos["usuarios"].items()):
                if isinstance(v, int):
                    datos["usuarios"][u] = {"tokens": v}

            return datos

    # Si no existe archivo
    return {
        "usuarios": {},
        "admin": {"username": "admin", "password": hash_password("admin")}
    }

def guardar_datos(datos):
    with open(DB_FILE, "w") as f:
        json.dump(datos, f, indent=4)

# ========= Inicializar estado ========= #
if "data" not in st.session_state:
    st.session_state["data"] = cargar_datos()
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
        admin = st.session_state["data"]["admin"]
        if username == admin["username"] and admin["password"] == hash_password(password):
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

# =================== Panel Admin =================== #
if st.session_state["logged_in"]:
    st.subheader("👑 Panel de Administración")

    # Mostrar usuarios
    st.write("📋 Lista de usuarios:")
    st.table([{"Usuario": u, "Tokens": d["tokens"]} for u, d in st.session_state["data"]["usuarios"].items()])

    # Añadir usuario
    st.divider()
    st.subheader("➕ Añadir usuario")
    nuevo_usuario = st.text_input("Nombre de usuario")
    if st.button("Añadir usuario"):
        if nuevo_usuario and nuevo_usuario not in st.session_state["data"]["usuarios"]:
            st.session_state["data"]["usuarios"][nuevo_usuario] = {"tokens": 0}
            guardar_datos(st.session_state["data"])
            st.success(f"Usuario {nuevo_usuario} añadido con 0 tokens")
            st.rerun()
        else:
            st.error("❌ Usuario vacío o ya existente")

    # Editar tokens
    st.divider()
    st.subheader("🎯 Editar tokens")
    if st.session_state["data"]["usuarios"]:
        usuario_sel = st.selectbox("Selecciona usuario", list(st.session_state["data"]["usuarios"].keys()))
        cambio = st.number_input("Cambiar tokens (puede ser negativo)", step=1)
        if st.button("Aplicar cambio"):
            st.session_state["data"]["usuarios"][usuario_sel]["tokens"] += cambio
            guardar_datos(st.session_state["data"])
            st.success(f"Tokens de {usuario_sel} actualizados")
            st.rerun()
    else:
        st.info("⚠️ No hay usuarios registrados")

    # Eliminar usuario
    st.divider()
    st.subheader("🗑️ Eliminar usuario")
    if st.session_state["data"]["usuarios"]:
        usuario_del = st.selectbox("Selecciona usuario a eliminar", list(st.session_state["data"]["usuarios"].keys()))
        if st.button("Eliminar usuario"):
            del st.session_state["data"]["usuarios"][usuario_del]
            guardar_datos(st.session_state["data"])
            st.success(f"Usuario {usuario_del} eliminado")
            st.rerun()
    else:
        st.info("⚠️ No hay usuarios para eliminar")

    # Cambiar credenciales de admin
    st.divider()
    st.subheader("🔐 Cambiar credenciales de Admin")
    nuevo_admin_user = st.text_input("Nuevo usuario (admin)", value=st.session_state["data"]["admin"]["username"])
    nuevo_admin_pass = st.text_input("Nueva contraseña", type="password")
    if st.button("Actualizar credenciales"):
        if nuevo_admin_user.strip() and nuevo_admin_pass.strip():
            st.session_state["data"]["admin"]["username"] = nuevo_admin_user
            st.session_state["data"]["admin"]["password"] = hash_password(nuevo_admin_pass)
            guardar_datos(st.session_state["data"])
            st.success("✅ Credenciales actualizadas. Vuelve a iniciar sesión.")
            logout()
        else:
            st.error("❌ Usuario o contraseña no pueden estar vacíos")

    logout()

# =================== Panel Usuario Normal =================== #
else:
    st.subheader("📊 Ranking de Usuarios y Tokens")
    if st.session_state["data"]["usuarios"]:
        usuarios_ordenados = sorted(
            st.session_state["data"]["usuarios"].items(),
            key=lambda x: x[1]["tokens"],
            reverse=True
        )
        for usuario, datos in usuarios_ordenados:
            st.markdown(f"**👤 {usuario}** — 🎟️ {datos['tokens']} tokens")
    else:
        st.info("⚠️ Aún no hay usuarios registrados")

    st.divider()
    login()
