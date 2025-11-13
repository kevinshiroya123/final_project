
#  Security Onion Log Analyzer (Streamlit + Elasticsearch + GPT)


import streamlit as st
import pandas as pd
import requests, json, csv, os, re
from openai import OpenAI
import llm_analysis  # GPT module for analysis and chat

#  CONFIG 
ES_INDEX = "windows-logs"
ES_BASE = "http://localhost:9200"
ES_BULK_URL = f"{ES_BASE}/{ES_INDEX}/_bulk?refresh=wait_for"
ES_SEARCH_URL = f"{ES_BASE}/{ES_INDEX}/_search"
ES_DELETE_URL = f"{ES_BASE}/{ES_INDEX}"
CHUNK_SIZE = 5000
CONFIG_PATH = "/Users/sls-kjs/Desktop/project/masters/code/secority onion/openai_model_code/config.py"



# Load OpenAI key and initialize GPT

def load_openai_key():
    """Load OpenAI API key from config.py."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("config", CONFIG_PATH)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    return getattr(config, "OPENAI_API_KEY", None)


api_key = load_openai_key()
if not api_key:
    st.error("OpenAI API key not found in config.py")
    st.stop()

llm_analysis.init_openai(api_key)
client = OpenAI(api_key=api_key)


# Step 1: Parse BOTSv1 CSV

def reconstruct_logs(input_path: str) -> str | None:
    """Parse BOTSv1 CSV logs, extract useful fields from '_raw'."""
    if not os.path.exists(input_path):
        st.error(f"File not found: {input_path}")
        return None

    st.info("� Loading CSV safely...")
    df = pd.read_csv(
        input_path,
        engine="python",
        quoting=csv.QUOTE_MINIMAL,
        quotechar='"',
        sep=",",
        on_bad_lines="skip",
        dtype=str,
    )

    if "_raw" not in df.columns:
        st.error("❌ '_raw' column not found.")
        return None

    def parse_raw(raw_text: str) -> dict:
        if pd.isna(raw_text):
            return {}
        raw_text = str(raw_text).replace("\r", "").strip()
        data = {}

        def find_field(name):
            m = re.search(rf"{name}\s*=\s*(.+)", raw_text)
            return m.group(1).strip() if m else None

        data["EventCode"] = find_field("EventCode")
        data["ComputerName"] = find_field("ComputerName")
        data["TaskCategory"] = find_field("TaskCategory")
        data["Keywords"] = find_field("Keywords")
        data["Message"] = find_field("Message")

        subj = re.search(r"Subject:\s*([\s\S]*?)\n\n", raw_text)
        if subj:
            block = subj.group(1)
            for k in ["Account Name", "Account Domain"]:
                m = re.search(rf"{k}:\s*(.+)", block)
                if m:
                    data[f"Subject_{k.replace(' ', '_')}"] = m.group(1).strip()

        proc = re.search(r"Process Information:\s*([\s\S]*?)\n\n", raw_text)
        if proc:
            block = proc.group(1)
            m = re.search(r"Process Name:\s*(.+)", block)
            if m:
                data["Process_Name"] = m.group(1).strip()

        enabled = re.findall(r"Enabled Privileges:\s*([\s\S]*?)\n\s*Disabled Privileges", raw_text)
        if enabled:
            lines = [ln.strip() for ln in enabled[0].splitlines() if ln.strip()]
            data["Enabled_Privileges"] = " | ".join(lines)

        data["_raw"] = raw_text
        return data

    parsed_df = pd.DataFrame(df["_raw"].apply(parse_raw).tolist())
    meta_df = df.drop(columns=["_raw"], errors="ignore")
    final_df = pd.concat([meta_df, parsed_df], axis=1)
    cols = [c for c in final_df.columns if c != "_raw"] + ["_raw"]
    final_df = final_df[cols]

# ENRICH WITH SEVERITY MAPPING

    def add_severity_column(final_df):
        severity_path = "/Users/sls-kjs/Desktop/project/masters/code/secority onion/windows-event-id-with-severity.csv"
        if os.path.exists(severity_path):
            try:
                sev_df = pd.read_csv(severity_path, encoding="utf-8")
                sev_df["EVENT_ID"] = sev_df["EVENT_ID"].astype(str)
                final_df["EventCode"] = final_df["EventCode"].astype(str)
                # Merge on EventCode <-> EVENT_ID
                final_df = final_df.merge(
                    sev_df[["EVENT_ID", "SEVERITY"]],
                    how="left",
                    left_on="EventCode",
                    right_on="EVENT_ID"
                ).drop(columns=["EVENT_ID"], errors="ignore")
                st.success("Severity column successfully added based on EventCode mapping.")
            except Exception as e:
                st.warning(f" Could not enrich severity data: {e}")
        else:
            st.warning("Severity mapping CSV not found at expected path.")
        return final_df

    final_df = add_severity_column(final_df)


    out_path = os.path.splitext(input_path)[0] + "_useful_parsed.csv"
    final_df.to_csv(out_path, index=False, quoting=csv.QUOTE_MINIMAL, quotechar='"', escapechar='\\')
    st.success(f"Parsed logs saved to: {out_path}")
    return out_path



# Step 2: Elasticsearch ingestion

def bulk_send(ndjson_lines: list[str]) -> dict:
    payload = "\n".join(ndjson_lines) + "\n"
    r = requests.post(
        ES_BULK_URL,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        timeout=60,
    )
    try:
        return {"status_code": r.status_code, "json": r.json()}
    except Exception:
        return {"status_code": r.status_code, "json": {"error": r.text[:400]}}


def upload_to_elasticsearch(df: pd.DataFrame):
    """Upload parsed logs into Elasticsearch."""
    df = df.drop(columns=["_raw"], errors="ignore")
    requests.delete(ES_DELETE_URL)
    st.warning("� Old Elasticsearch index deleted.")
    requests.put(f"{ES_BASE}/{ES_INDEX}", json={"settings": {"number_of_shards": 1}})
    st.success(f"� Index '{ES_INDEX}' created.")

    buf, sent = [], 0
    for _, row in df.iterrows():
        doc = {k: (v if isinstance(v, str) else str(v)) for k, v in row.to_dict().items()}
        buf.append(json.dumps({"index": {"_index": ES_INDEX}}))
        buf.append(json.dumps(doc))
        if len(buf) >= CHUNK_SIZE * 2:
            bulk_send(buf)
            sent += len(buf) // 2
            buf = []
    if buf:
        bulk_send(buf)
        sent += len(buf) // 2
    st.success(f"Ingested {sent} logs into '{ES_INDEX}'.")


def verify_elasticsearch(limit=10):
    q = {"query": {"match_all": {}}, "size": limit}
    r = requests.post(ES_SEARCH_URL, json=q)
    if r.status_code == 200:
        hits = r.json().get("hits", {}).get("hits", [])
        return pd.DataFrame([h["_source"] for h in hits]) if hits else pd.DataFrame()
    return pd.DataFrame()


# Streamlit UI

st.set_page_config(page_title="Security Onion Log Analyzer (AI)", layout="wide")
st.title("Security Onion Log Analyzer + GPT SOC Assistant")

uploaded = st.file_uploader("Upload your raw BOTSv1 CSV log file", type=["csv"])

if uploaded:
    # Clear old state when new file uploaded
    if "uploaded_name" not in st.session_state or uploaded.name != st.session_state["uploaded_name"]:
        st.session_state.clear()
        requests.delete(ES_DELETE_URL)
        st.warning(" Old session data and Elasticsearch index cleared.")
        st.session_state["uploaded_name"] = uploaded.name

    save_path = os.path.join(os.getcwd(), uploaded.name)
    with open(save_path, "wb") as f:
        f.write(uploaded.getbuffer())
    st.success(f" File saved to {save_path}")

    parsed_path = reconstruct_logs(save_path)
    if parsed_path:
        df = pd.read_csv(parsed_path, dtype=str).fillna("")
        st.session_state["parsed_df"] = df
        st.info(f"Parsed {len(df)} logs.")
        st.dataframe(df.head(10), use_container_width=True)

        if st.button(" Ingest into Elasticsearch", key="ingest_btn"):
            upload_to_elasticsearch(df)
            es_df = verify_elasticsearch(limit=100)
            if not es_df.empty:
                st.session_state["es_df"] = es_df
                st.session_state["log_data"] = es_df.to_dict(orient="records")
                st.success("Logs ingested successfully!")




# Search, GPT Summary, Chatbot

es_df = st.session_state.get("es_df", pd.DataFrame())


# VISUALIZATIONS SECTION

st.divider()
st.subheader("SOC Visualization Dashboard")

if not es_df.empty:

    # 1️--- Event Code Frequency ---
    st.markdown("### Top 10 Event Codes by Frequency")
    if "EventCode" in es_df.columns:
        top_events = es_df["EventCode"].value_counts().head(10)
        st.bar_chart(top_events)

    # 2️ --- Severity Distribution ---
    st.markdown("### Severity Distribution (High / Medium / Low)")
    if "SEVERITY" in es_df.columns:
        sev_counts = es_df["SEVERITY"].value_counts()
        st.bar_chart(sev_counts)

    # 3️--- Events per Host ---
    st.markdown("### Top 10 Most Active Hosts")
    if "ComputerName" in es_df.columns:
        top_hosts = es_df["ComputerName"].value_counts().head(10)
        st.bar_chart(top_hosts)

    # 4️ --- Severity by Event Code (Heatmap) ---
    st.markdown("###  Event Code vs Severity Correlation")
    import matplotlib.pyplot as plt
    import seaborn as sns

    if "EventCode" in es_df.columns and "SEVERITY" in es_df.columns:
        heatmap_data = pd.crosstab(es_df["EventCode"], es_df["SEVERITY"])
        fig, ax = plt.subplots()
        sns.heatmap(heatmap_data, annot=True, fmt="d", cmap="YlOrRd", ax=ax)
        st.pyplot(fig)

    # 5️--- Event Timeline (if timestamp exists) ---
    st.markdown("###  Event Timeline (if timestamps available)")
    time_cols = [c for c in es_df.columns if "time" in c.lower() or "timestamp" in c.lower()]
    if time_cols:
        time_col = time_cols[0]
        try:
            es_df[time_col] = pd.to_datetime(es_df[time_col], errors="coerce")
            time_series = es_df.groupby(es_df[time_col].dt.date).size()
            st.line_chart(time_series)
        except Exception as e:
            st.warning(f" Could not create timeline chart: {e}")
    else:
        st.info(" No timestamp field detected; skipping timeline chart.")
else:
    st.info(" Upload and ingest logs to see visualization dashboard.")


if not es_df.empty:
    # --- SEARCH FIRST ---
    st.divider()
    st.subheader(" Search Logs")

    search_query = st.text_input("Search logs (by EventCode, ComputerName, Message, etc.):", key="search_input")
    if search_query:
        try:
            search_num = int(search_query)
        except ValueError:
            search_num = None

        def row_matches(row):
            for val in row:
                if re.search(str(search_query), str(val), re.IGNORECASE):
                    return True
                if search_num is not None:
                    try:
                        if int(str(val)) == search_num:
                            return True
                    except Exception:
                        continue
            return False

        mask = es_df.apply(row_matches, axis=1)
        filtered_df = es_df[mask]
        st.dataframe(filtered_df, use_container_width=True)
    else:
        st.dataframe(es_df, use_container_width=True)

    # --- GPT SUMMARY NEXT ---
    st.divider()
    st.subheader(" AI Security Summary")
    # --- make everything JSON-safe before sending to GPT ---
    def make_json_safe(df: pd.DataFrame) -> pd.DataFrame:
        """Convert timestamps and other non-JSON types to strings."""
        df = df.copy()
        for col in df.columns:
            df[col] = df[col].apply(
                lambda x: x.isoformat() if isinstance(x, (pd.Timestamp,)) else
                        (None if pd.isna(x) else str(x))
            )
        return df

    safe_es_df = make_json_safe(es_df)
    summary = st.session_state.get("gpt_summary") or llm_analysis.analyze_logs_with_gpt(
        safe_es_df.to_dict(orient="records")
    )

    st.session_state["gpt_summary"] = summary
    st.write(summary)

    # --- CHATBOT LAST ---
    st.divider()
    st.subheader(" SOC Chatbot")
    llm_analysis.chat_with_logs("soc_chat")
