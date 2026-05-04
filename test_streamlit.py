import streamlit as st
import sys

st.set_page_config(page_title="Streamlit Test", page_icon="✅")

st.title("Streamlit is Working!")
st.write(f"**Python Version:** {sys.version}")
st.write(f"**Streamlit Version:** {st.__version__}")

st.success("If you are seeing this page in your browser, your installation is successful.")
st.balloons()