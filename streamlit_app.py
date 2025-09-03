import streamlit as st
import json
import os
import hashlib

# ------------------ UTILIDADES ------------------ #
DB_FILE = "usuarios.json"
ADMIN_FILE = "admin.json"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Cargar o inicializar base de usuarios
def load_data():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f)
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Cargar o inicializar credenciales admin
def load_admin():
    if not os.path.exists(ADMIN_FILE):
        default = {"username": "admin", "password": hash_password("admin")}
        with open(ADMIN_FILE, "w") as f:
            json.dump(default, f, indent=4)
    with open(ADMIN_FILE, "r") as f:
        return json.load(f)

def save_admin(admin_data):
    with open(ADMIN_FILE, "w") as f:
        json.dump(admin_data, f, indent=4)

# ------------------ LOGIN / LOGOUT ------------------ #
def login():
    st.subheader("🔑 Iniciar Sesión de Administrador")
    username = st.text_input("Usuario", key="login_user")
    password = st.text_input("Contraseña", type="password", key="login_pass")

    if st.button("Iniciar Sesión", key="login_button"):
        admin = load_admin()
        if username == admin["username"] and hash_password(password) == admin["password"]:
            st.session_state["logged_in"] = True
            st.success("✅ Sesión iniciada")
            st.rerun()
        else:
            st.error("❌ Usuario o contraseña incorrectos")

def logout():
    if st.button("Cerrar Sesión", key="logout_button"):
        st.session_state["logged_in"] = False
        st.success("Sesión cerrada correctamente")
        st.rerun()

# ------------------ FUNCIONES DE ADMIN ------------------ #
def admin_panel():
    st.title("⚙️ Panel de Administración")
    logout()
    st.divider()

    data = load_data()

    # Añadir usuario
    with st.expander("➕ Añadir Usuario"):
        new_user = st.text_input("Nombre del usuario", key="new_user")
        if st.button("Guardar Usuario", key="add_user_button"):
            if new_user in data:
                st.warning("⚠️ El usuario ya existe")
            else:
                data[new_user] = 0
                save_data(data)
                st.success(f"Usuario '{new_user}' añadido")

    # Editar o eliminar usuarios
    with st.expander("✏️ Editar / Eliminar Usuario"):
        if data:
            selected_user = st.selectbox("Seleccionar usuario", list(data.keys()), key="select_user_admin")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("Eliminar Usuario", key="delete_user_button"):
                    del data[selected_user]
                    save_data(data)
                    st.success(f"Usuario '{selected_user}' eliminado")
                    st.rerun()
            with col2:
                new_name = st.text_input("Nuevo nombre", key="edit_user_name")
                if st.button("Actualizar Nombre", key="update_user_button"):
                    if new_name:
                        data[new_name] = data.pop(selected_user)
                        save_data(data)
                        st.success("Nombre actualizado")
                        st.rerun()
        else:
            st.info("No hay usuarios registrados")

    # Gestionar tokens
    with st.expander("🎟️ Gestionar Tokens"):
        if data:
            selected_user = st.selectbox("Seleccionar usuario", list(data.keys()), key="select_user_tokens")
            st.write(f"Tokens actuales: **{data[selected_user]}**")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("➕ Añadir Token", key="add_token_button"):
                    data[selected_user] += 1
                    save_data(data)
                    st.success("Token añadido")
                    st.rerun()
            with col2:
                if st.button("➖ Quitar Token", key="remove_token_button"):
                    data[selected_user] -= 1
                    save_data(data)
                    st.success("Token eliminado")
                    st.rerun()
        else:
            st.info("No hay usuarios registrados")

    # Cambiar credenciales admin
    with st.expander("🔐 Cambiar Credenciales de Admin"):
        new_user = st.text_input("Nuevo usuario admin", key="new_admin_user")
        new_pass = st.text_input("Nueva contraseña admin", type="password", key="new_admin_pass")

        if st.button("Actualizar Credenciales", key="update_admin_button"):
            if new_user and new_pass:
                save_admin({"username": new_user, "password": hash_password(new_pass)})
                st.success("Credenciales de admin actualizadas. Vuelve a iniciar sesión.")
                st.session_state["logged_in"] = False
                st.rerun()
            else:
                st.warning("Debes ingresar ambos campos")

# ------------------ VISTA DE USUARIO ------------------ #
def user_view():
    st.title("👥 Lista de Usuarios y Tokens")
    data = load_data()

    if data:
        for user, tokens in data.items():
            st.markdown(f"**{user}** — 🎟️ {tokens} tokens")
    else:
        st.info("No hay usuarios registrados aún")

# ------------------ MAIN ------------------ #
def main():
    st.set_page_config(page_title="Gestor de Usuarios y Tokens", page_icon="🎟️", layout="centered")

    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if st.session_state["logged_in"]:
        admin_panel()
    else:
        user_view()
        st.divider()
        login()

if __name__ == "__main__":
    main()
