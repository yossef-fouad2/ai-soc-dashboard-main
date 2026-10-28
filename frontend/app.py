import streamlit as st
import requests
import pandas as pd
import time
import json
API = "http://localhost:8000"
st.set_page_config(
    layout="wide",
    page_title="AI SOC Dashboard",
    page_icon="🛡️"
)
st.markdown("## 🛡️ AI SOC Dashboard")
st.caption("Real-time anomaly detection + AI threat analysis")
if "data" not in st.session_state:
    st.session_state.data = None
if "last_run" not in st.session_state:
    st.session_state.last_run = None
if "explanations" not in st.session_state:
    st.session_state.explanations = {}
st.sidebar.title("⚙️ Controls")
auto_refresh = st.sidebar.checkbox("Auto Refresh (5s)")
run_btn = st.sidebar.button("Run Analysis")
def fetch_data():
    try:
        res = requests.get(f"{API}/analyze", timeout=10)
        if res.status_code != 200:
            st.sidebar.error("API Error")
            return None
        data = res.json()
        return data.get("alerts", [])
    except requests.exceptions.ConnectionError:
        st.sidebar.error("Backend not reachable")
        return None
    except requests.exceptions.Timeout:
        st.sidebar.error("Analysis timed out. Restart the updated backend and try again.")
        return None
    except Exception as e:
        st.sidebar.error(f"Error: {str(e)}")
        return None
if run_btn or auto_refresh:
    new_data = fetch_data()
    if new_data is not None:
        st.session_state.data = new_data
        st.session_state.last_run = time.strftime("%H:%M:%S")
data = st.session_state.data
if not data:
    st.info("Click 'Run Analysis' to start")
    st.stop()
df = pd.DataFrame(data)
st.subheader("📊 System Overview")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Logs", len(df))
col2.metric("High Alerts", len(df[df["severity"] == "High"]))
col3.metric("Critical Alerts", len(df[df["severity"] == "Critical"]))
col4.metric("Last Run", st.session_state.last_run or "-")
st.subheader("📈 Severity Distribution")
severity_counts = df["severity"].value_counts()
st.bar_chart(severity_counts)
st.subheader("🔍 Filter Alerts")
selected = st.multiselect(
    "Select Severity",
    options=df["severity"].unique(),
    default=df["severity"].unique()
)
filtered_df = df[df["severity"].isin(selected)]
st.subheader("📋 Alerts Table")
table_df = filtered_df[["severity", "rules"]].copy()
table_df["rules"] = table_df["rules"].map(
    lambda hits: ", ".join(rule["name"] for rule in hits) or "No rules triggered"
)
st.dataframe(table_df, use_container_width=True)
st.subheader("🚨 Critical & High Alerts")
for i, item in enumerate(data):
    if item["severity"] in ["High", "Critical"]:
        color = "red" if item["severity"] == "Critical" else "orange"
        with st.container():
            st.markdown(f"### 🔥 :{color}[{item['severity']} Alert]")
            col1, col2 = st.columns([1, 2])
            with col1:
                st.json(item["log"])
            with col2:
                st.markdown("**Explanation:**")
                log_key = json.dumps(item["log"], sort_keys=True)
                if st.button("Generate AI Explanation", key=f"explain_{log_key}_{i}"):
                    with st.spinner("Generating explanation with Ollama..."):
                        try:
                            res = requests.post(
                                f"{API}/explain",
                                json={"log": item["log"]},
                                timeout=(3, 45)
                            )
                            res.raise_for_status()
                            st.session_state.explanations[log_key] = res.json()["explanation"]
                        except requests.exceptions.Timeout:
                            st.error("AI explanation timed out. Check Ollama and try again.")
                        except requests.exceptions.RequestException as e:
                            st.error(f"AI explanation unavailable: {e}")
                explanation = st.session_state.explanations.get(log_key) or item.get("explanation")
                if explanation:
                    if explanation.startswith("LLM Error:"):
                        st.error(explanation)
                    else:
                        st.write(explanation)
                else:
                    st.caption("Generate an AI explanation for this alert when needed.")
            st.divider()
if auto_refresh:
    time.sleep(5)
    st.rerun()
