import streamlit as st
import jks
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
import io
import os
import zipfile
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
    - Download updated keystore, PFX, or ZIP of certificates.
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
                    try:
                        # Parse private key to get algorithm and key size
                        private_key = serialization.load_der_private_key(
                            entry.pkey, password=None, backend=default_backend()
                        )
                        algorithm = private_key.__class__.__name__.replace("PrivateKey", "")
                        key_size = private_key.key_size if hasattr(private_key, "key_size") else "N/A"
                        
                        with col1:
                            st.write(f"**Algorithm:** {algorithm}")
                            st.write(f"**Key Size:** {key_size} bits")
                        with col2:
                            st.write(f"**Chain Length:** {len(entry.cert_chain)}")
                    except Exception as e:
                        st.error(f"Error parsing private key for {alias}: {e}")
                        continue
                    
                    # Cert chain
                    for i, (cert_name, cert_der) in enumerate(entry.cert_chain):
                        st.write(f"**Cert {i+1}:** {cert_name}")
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        st.write(f"**Subject:** {cert.subject.rfc4514_string()}")
                        st.write(f"**Issuer:** {cert.issuer.rfc4514_string()}")
                        st.write(f"**Valid From:** {cert.not_valid_before}")
                        st.write(f"**Valid Until:** {cert.not_valid_after}")
                    
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
                        st.write(f"**Valid Until:** {cert.not_valid_after}")
                    
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
        
        # Import Trusted Cert
        st.markdown("### Import as Trusted Certificate")
        uploaded_cert = st.file_uploader("Choose a certificate file (PEM/DER)", type=["pem", "der", "crt", "cer"], key="trusted_uploader")
        new_alias_trusted = st.text_input("New Alias (Trusted)", key="trusted_alias")
        if st.button("Import as Trusted Cert") and uploaded_cert and new_alias_trusted:
            try:
                cert_data = uploaded_cert.read()
                if uploaded_cert.name.lower().endswith('.pem'):
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                else:
                    cert_der = cert_data
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Add to keystore
                tce = jks.TrustedCertEntry(new_alias_trusted, cert_der)
                ks.certs[new_alias_trusted] = tce
                st.success(f"Imported trusted certificate for alias '{new_alias_trusted}'")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to import trusted cert: {e}")
        
        # Import PFX (Private Key + Cert)
        st.markdown("### Import Private Key + Personal Certificate (PFX/P12)")
        uploaded_pfx = st.file_uploader("Choose a PFX/P12 file", type=["pfx", "p12"], key="pfx_uploader")
        pfx_password = st.text_input("PFX Password", type="password", key="pfx_pass")
        new_alias_pfx = st.text_input("New Alias (PrivateKey)", key="pfx_alias")
        if st.button("Import PFX as PrivateKeyEntry") and uploaded_pfx and pfx_password and new_alias_pfx:
            try:
                pfx_data = uploaded_pfx.read()
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, pfx_password.encode(), default_backend())
                
                # Serialize private key to DER PKCS#8
                pkey_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Build cert chain: end-entity first, then additional
                cert_chain = []
                cert_chain.append((new_alias_pfx, cert.public_bytes(serialization.Encoding.DER)))
                for add_cert in additional_certs:
                    chain_alias = f"{new_alias_pfx}_intermediate"
                    cert_chain.append((chain_alias, add_cert.public_bytes(serialization.Encoding.DER)))
                
                # Create PrivateKeyEntry
                pke = jks.PrivateKeyEntry(new_alias_pfx, pkey_der, cert_chain)
                ks.private_keys[new_alias_pfx] = pke
                st.success(f"Imported private key + cert chain for alias '{new_alias_pfx}'")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to import PFX: {e}")

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
        
        # Export entire keystore as JKS
        st.markdown("### Download Updated Keystore (JKS)")
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

        # Export entire keystore as PFX
        st.markdown("### Convert Entire Keystore to PFX")
        pfx_all_password = st.text_input("PFX Password (for all entries)", type="password", key="pfx_all_pass")
        if st.button("Convert JKS to PFX") and pfx_all_password:
            try:
                # Create a ZIP-like structure in memory for PFX files (simulating multiple entries)
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for alias, entry in ks.private_keys.items():
                        private_key = serialization.load_der_private_key(entry.pkey, password=None, backend=default_backend())
                        certs = [x509.load_der_x509_certificate(cert_der, default_backend()) for _, cert_der in entry.cert_chain]
                        primary_cert = certs[0] if certs else None
                        additional_certs = certs[1:] if len(certs) > 1 else []
                        
                        # Serialize each private key entry to PFX
                        pfx_data = pkcs12.serialize_key_and_certificates(
                            name=alias.encode(),
                            key=private_key,
                            cert=primary_cert,
                            cas=additional_certs,
                            encryption_algorithm=serialization.BestAvailableEncryption(pfx_all_password.encode())
                        )
                        zf.writestr(f"{alias}.pfx", pfx_data)
                    
                    # Add trusted certificates as additional certs in a single PFX
                    trusted_certs = [x509.load_der_x509_certificate(entry.cert, default_backend()) for _, entry in ks.certs.items()]
                    if trusted_certs:
                        pfx_data = pkcs12.serialize_key_and_certificates(
                            name=b"trusted_certs",
                            key=None,  # No private key for trusted certs
                            cert=None,  # No primary cert
                            cas=trusted_certs,
                            encryption_algorithm=serialization.BestAvailableEncryption(pfx_all_password.encode())
                        )
                        zf.writestr("trusted_certs.pfx", pfx_data)
                
                zip_buffer.seek(0)
                st.download_button(
                    label="Download All Entries as PFX (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name=f"keystore_pfx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                    mime="application/zip"
                )
                st.success("Converted JKS to PFX files (zipped)")
            except Exception as e:
                st.error(f"Failed to convert JKS to PFX: {e}")

        # Export private key + certificate as PFX
        st.markdown("### Export Private Key + Certificate as PFX")
        private_key_aliases = list(ks.private_keys.keys())
        if private_key_aliases:
            selected_pfx_alias = st.selectbox("Select Private Key Alias to Export as PFX", private_key_aliases, key="pfx_export_alias")
            pfx_export_password = st.text_input("PFX Export Password", type="password", key="pfx_export_pass")
            if st.button("Export as PFX") and pfx_export_password:
                try:
                    entry = ks.private_keys[selected_pfx_alias]
                    private_key = serialization.load_der_private_key(entry.pkey, password=None, default_backend())
                    
                    # Load certificates from chain
                    certs = []
                    for _, cert_der in entry.cert_chain:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        certs.append(cert)
                    
                    # Primary certificate is first in chain
                    primary_cert = certs[0] if certs else None
                    additional_certs = certs[1:] if len(certs) > 1 else []
                    
                    # Serialize to PFX
                    pfx_data = pkcs12.serialize_key_and_certificates(
                        name=selected_pfx_alias.encode(),
                        key=private_key,
                        cert=primary_cert,
                        cas=additional_certs,
                        encryption_algorithm=serialization.BestAvailableEncryption(pfx_export_password.encode())
                    )
                    
                    st.download_button(
                        label="Download PFX",
                        data=pfx_data,
                        file_name=f"{selected_pfx_alias}.pfx",
                        mime="application/x-pkcs12"
                    )
                    st.success(f"Exported private key + cert chain for '{selected_pfx_alias}' as PFX")
                except Exception as e:
                    st.error(f"Failed to export PFX: {e}")
        else:
            st.info("No private key entries available to export as PFX.")

        # Export all certificates as ZIP
        st.markdown("### Export All Certificates as ZIP")
        if st.button("Export All Certificates as ZIP"):
            try:
                # Create ZIP in memory
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    # Private key certificates
                    for alias, entry in ks.private_keys.items():
                        for i, (cert_name, cert_der) in enumerate(entry.cert_chain):
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            pem_data = cert.public_bytes(serialization.Encoding.PEM)
                            cert_type = "end_entity" if i == 0 else "intermediate" if i < len(entry.cert_chain) - 1 else "root"
                            zf.writestr(f"{alias}_{cert_type}.pem", pem_data)
                    
                    # Trusted certificates
                    for alias, entry in ks.certs.items():
                        cert = x509.load_der_x509_certificate(entry.cert, default_backend())
                        pem_data = cert.public_bytes(serialization.Encoding.PEM)
                        zf.writestr(f"trusted_{alias}.pem", pem_data)
                
                zip_buffer.seek(0)
                st.download_button(
                    label="Download All Certificates (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name=f"certificates_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                    mime="application/zip"
                )
                st.success("Exported all certificates as ZIP")
            except Exception as e:
                st.error(f"Failed to export certificates as ZIP: {e}")

else:
    st.info("👆 Upload a JKS file and enter password to get started.")

# Clean up temp file on rerun if needed
if st.button("Clear Session"):
    if st.session_state.temp_jks_path and os.path.exists(st.session_state.temp_jks_path):
        os.remove(st.session_state.temp_jks_path)
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()
