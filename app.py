import streamlit as st
import jks
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import io
import base64
from datetime import datetime

# Page config
st.set_page_config(page_title="JKS Explorer", page_icon="🔑", layout="wide")

st.title("🔑 JKS Keystore Explorer & Manager")
st.markdown("Upload a JKS file to explore, import/export certificates, add/remove entries, and more.")

# Sidebar for instructions
with st.sidebar:
    st.header("Instructions")
    st.markdown("""
    - Upload your JKS file and enter the keystore password.
    - Explore entries below.
    - Use buttons to export, delete, or import.
    - Download updated keystore after changes.
    **Security Note:** Handle passwords and files securely. This app runs locally.
    """)
    st.markdown("### Requirements")
    st.code("""
pip install streamlit pyjks cryptography
    """)

# Main app
if "keystore" not in st.session_state:
    st.session_state.keystore = None
    st.session_state.password = None
    st.session_state.temp_jks_path = None

# Upload JKS
uploaded_jks = st.file_uploader("Choose a JKS file", type="jks")
password = st.text_input("Keystore Password", type="password")

if uploaded_jks is not None and password:
    try:
        # Save uploaded file to temp
        if st.session_state.temp_jks_path is None:
            with open("temp.jks", "wb") as f:
                f.write(uploaded_jks.getvalue())
            st.session_state.temp_jks_path = "temp.jks"

        # Load keystore
        ks = jks.KeyStore.load(st.session_state.temp_jks_path, password)
        st.session_state.keystore = ks
        st.session_state.password = password
        st.success("Keystore loaded successfully!")
    except Exception as e:
        st.error(f"Failed to load keystore: {e}")
        st.session_state.keystore = None

if st.session_state.keystore:
    ks = st.session_state.keystore
    passw = st.session_state.password

    # Tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Explore Entries", "📥 Import Cert", "🗑️ Delete Entry", "💾 Export/Download"])

    with tab1:
        st.subheader("Explore Entries")
        
        # Private Keys
        if ks.private_keys:
            st.subheader("🔐 Private Key Entries")
            for alias, entry in ks.private_keys.items():
                with st.expander(f"{alias} (PrivateKeyEntry)"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Algorithm:** {entry.algorithm}")
                        st.write(f"**Key Size:** {entry.key_size} bits")
                    with col2:
                        st.write(f"**Chain Length:** {len(entry.cert_chain)}")
                    
                    # Cert chain
                    for i, (cert_name, cert_der) in enumerate(entry.cert_chain):
                        st.write(f"**Cert {i+1}:** {cert_name}")
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        st.write(f"**Subject:** {cert.subject.rfc4514_string()}")
                        st.write(f"**Issuer:** {cert.issuer.rfc4514_string()}")
                        st.write(f"**Valid From:** {cert.not_valid_before}")
                        st.write(f"**Valid Until:** {cert.not_valid_until}")
                    
                    # Export cert button (first in chain)
                    if entry.cert_chain:
                        if st.button(f"Export Chain Cert as PEM ({alias})", key=f"exp_pk_{alias}"):
                            pem_data = io.StringIO()
                            for _, cert_der in entry.cert_chain:
                                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                                pem = cert.public_bytes(serialization.Encoding.PEM)
                                pem_data.write(pem.decode('utf-8'))
                            st.download_button(
                                label="Download PEM Chain",
                                data=pem_data.getvalue(),
                                file_name=f"{alias}_chain.pem",
                                mime="text/plain"
                            )

        # Trusted Certs
        if ks.certs:
            st.subheader("📜 Trusted Certificate Entries")
            for alias, entry in ks.certs.items():
                with st.expander(f"{alias} (TrustedCertEntry)"):
                    cert = x509.load_der_x509_certificate(entry.cert, default_backend())
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Subject:** {cert.subject.rfc4514_string()}")
                        st.write(f"**Issuer:** {cert.issuer.rfc4514_string()}")
                    with col2:
                        st.write(f"**Valid From:** {cert.not_valid_before}")
                        st.write(f"**Valid Until:** {cert.not_valid_until}")
                    
                    # Export button
                    if st.button(f"Export Cert as PEM ({alias})", key=f"exp_tc_{alias}"):
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        st.download_button(
                            label="Download PEM",
                            data=pem,
                            file_name=f"{alias}.pem",
                            mime="text/plain"
                        )

        # Secret Keys
        if ks.secret_keys:
            st.subheader("🔑 Secret Key Entries")
            for alias, entry in ks.secret_keys.items():
                with st.expander(f"{alias} (SecretKeyEntry)"):
                    st.write(f"**Algorithm:** {entry.algorithm}")
                    st.write(f"**Key Size:** {entry.key_size} bits")
                    # Note: Key bytes not displayed for security

    with tab2:
        st.subheader("Import Certificate")
        uploaded_cert = st.file_uploader("Choose a certificate file (PEM/DER)", type=["pem", "der", "crt", "cer"])
        new_alias = st.text_input("New Alias")
        if st.button("Import as Trusted Cert") and uploaded_cert and new_alias:
            try:
                cert_data = uploaded_cert.read()
                if uploaded_cert.name.endswith('.pem'):
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                else:
                    cert_der = cert_data
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Add to keystore
                tce = jks.TrustedCertEntry(new_alias, cert_der)
                ks.certs[new_alias] = tce
                st.success(f"Imported certificate for alias '{new_alias}'")
            except Exception as e:
                st.error(f"Failed to import: {e}")

    with tab3:
        st.subheader("Delete Entry")
        all_aliases = list(ks.private_keys.keys()) + list(ks.certs.keys()) + list(ks.secret_keys.keys())
        selected_alias = st.selectbox("Select Alias to Delete", all_aliases)
        entry_type = next((k for k, v in [("Private", ks.private_keys), ("TrustedCert", ks.certs), ("Secret", ks.secret_keys)] if selected_alias in v), None)
        st.info(f"Type: {entry_type}Entry")
        
        if st.button(f"Delete '{selected_alias}'"):
            if entry_type == "Private":
                del ks.private_keys[selected_alias]
            elif entry_type == "TrustedCert":
                del ks.certs[selected_alias]
            elif entry_type == "Secret":
                del ks.secret_keys[selected_alias]
            st.success(f"Deleted '{selected_alias}'")
            st.rerun()  # Refresh

    with tab4:
        st.subheader("Export & Download")
        
        # Export specific cert (reuse from explore, but here full keystore download)
        st.markdown("### Download Updated Keystore")
        if st.button("Download Updated JKS"):
            # Save to bytes
            output = io.BytesIO()
            ks.save(output, passw)
            output.seek(0)
            st.download_button(
                label="Download JKS",
                data=output.getvalue(),
                file_name=f"updated_keystore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jks",
                mime="application/octet-stream"
            )

        # Option to export all certs
        if st.button("Export All Certificates as ZIP (TODO: Implement ZIP)"):
            st.info("ZIP export not implemented in this version. Use individual exports above.")

else:
    st.info("👆 Upload a JKS file and enter password to get started.")

# Clean up temp file on rerun if needed, but Streamlit handles
if st.button("Clear Session"):
    if st.session_state.temp_jks_path and os.path.exists(st.session_state.temp_jks_path):
        os.remove(st.session_state.temp_jks_path)
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()
