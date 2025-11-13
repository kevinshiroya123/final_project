
#  Security Onion Log Analyzer (Streamlit + Elasticsearch + Kibana Integration + GPT)
#  Added console print statements for debugging and Kibana data view linking


import streamlit as st
import pandas as pd
import requests, json, csv, os, re, traceback
from openai import OpenAI
import llm_analysis  # GPT module for analysis and chat

#  CONFIG 
ES_BASE = "http://localhost:9200"  # Localhost Elasticsearch endpoint
KIBANA_BASE = "http://localhost:5601"  # Kibana endpoint
ES_INDEX = "windows-logs"
HEADERS = {"Content-Type": "application/json"}
CHUNK_SIZE = 5000
CONFIG_PATH = "/Users/sls-kjs/Desktop/project/masters/code/secority onion/config.py"



def debug_log(message):
    print(f"[DEBUG] {message}")


# Kibana Integration Helpers

def create_kibana_data_view(index_name="windows-logs"):
    try:
        payload = {
            "data_view": {
                "title": f"{index_name}*",
                "name": index_name,
                "timeFieldName": "@timestamp" if "@timestamp" in index_name else None,
            }
        }
        headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
        debug_log(f"Creating Kibana data view for index '{index_name}'.")
        r = requests.post(f"{KIBANA_BASE}/api/data_views/data_view", json=payload, headers=headers)
        if r.status_code in [200, 201]:
            debug_log(f"Kibana Data View '{index_name}' created successfully.")
            st.success(f" Kibana Data View '{index_name}' created.")
        elif r.status_code == 409:
            debug_log(f"Kibana Data View '{index_name}' already exists.")
            st.info(f"ℹ️ Kibana Data View '{index_name}' already exists.")
        else:
            st.error(f" Failed to create Data View: {r.status_code} {r.text}")
            debug_log(f"Failed to create Kibana Data View: {r.status_code} {r.text}")
    except Exception as e:
        debug_log(f"Error creating Kibana Data View: {e}")
        traceback.print_exc()


# Upload Data to Elasticsearch and Connect to Kibana

def upload_to_elasticsearch(df, index_name: str = ES_INDEX):
    try:
        if df.empty:
            st.warning(" No data to upload.")
            debug_log("Upload aborted: DataFrame is empty.")
            return

        debug_log(f"Deleting index '{index_name}' if exists.")
        requests.delete(f"{ES_BASE}/{index_name}")

        debug_log(f"Creating new index '{index_name}'.")
        requests.put(f"{ES_BASE}/{index_name}", json={"settings": {"number_of_shards": 1, "number_of_replicas": 0}})

        buf = []
        for _, row in df.iterrows():
            doc = {k: str(v) for k, v in row.to_dict().items()}
            buf.append(json.dumps({"index": {"_index": index_name}}))
            buf.append(json.dumps(doc))
        data = "\n".join(buf) + "\n"

        debug_log(f"Uploading {len(df)} documents to Elasticsearch index '{index_name}'.")
        r = requests.post(f"{ES_BASE}/{index_name}/_bulk?refresh=wait_for", data=data.encode("utf-8"), headers={"Content-Type": "application/x-ndjson"})

        if r.status_code < 300:
            st.success(f" Uploaded {len(df)} records to Elasticsearch index '{index_name}'.")
            debug_log(f"Successfully uploaded {len(df)} documents.")

            # --- Automatically create Kibana Data View ---
            create_kibana_data_view(index_name)

            st.markdown(f"[Open in Kibana Discover]({KIBANA_BASE}/app/discover#/view?_a=(index:'{index_name}'))")
        else:
            st.error(f" Upload failed: {r.status_code} {r.text[:400]}")
            debug_log(f"Upload failed: {r.status_code} {r.text}")
    except Exception as e:
        st.error(f" Elasticsearch upload failed: {e}")
        debug_log(f"Error during Elasticsearch upload: {e}")
        traceback.print_exc()


# Example Function to Verify Connection

def verify_connections():
    try:
        es_status = requests.get(f"{ES_BASE}").status_code
        kibana_status = requests.get(f"{KIBANA_BASE}/api/status", headers={"kbn-xsrf": "true"}).status_code
        debug_log(f"Elasticsearch Status: {es_status}, Kibana Status: {kibana_status}")
        if es_status == 200 and kibana_status == 200:
            st.success(" Connected successfully to both Elasticsearch and Kibana.")
        else:
            st.warning(f" Connection check failed. Elasticsearch={es_status}, Kibana={kibana_status}")
    except Exception as e:
        st.error(f" Connection check failed: {e}")
        debug_log(f"Connection check failed: {e}")


# Streamlit UI

st.set_page_config(page_title="Security Onion Log Analyzer (Localhost)", layout="wide")
st.title(" Security Onion Log Analyzer + Kibana Auto-Link (Elasticsearch + GPT)")

verify_connections()

uploaded = st.file_uploader(" Upload your raw BOTSv1 CSV log file", type=["csv"])
if uploaded:
    df = pd.read_csv(uploaded, dtype=str).fillna("")
    st.dataframe(df.head(5), use_container_width=True)
    if st.button("Upload & Create Kibana Data View"):
        upload_to_elasticsearch(df)