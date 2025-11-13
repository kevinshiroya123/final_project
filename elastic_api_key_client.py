
#  Elastic Cloud API-Key Client for Security Onion Analyzer


import json, requests, streamlit as st

# --- Elastic Cloud configuration ---
ES_BASE = "https://my-security-project-b47679.es.us-central1.gcp.elastic.cloud"      # e.g. https://abc123.us-central1.gcp.cloud.es.io
ES_INDEX = "soc-ai-logs"
ES_API_KEY = "dUpGUVI1b0I5aFl5NG4zWDd0XzY6ZWU5bVh5cm8xUWY3Q3pYR01MMUN6Zw=="  # your key
HEADERS = {
    "Authorization": f"ApiKey {ES_API_KEY}",
    "Content-Type": "application/x-ndjson"
}



# Upload parsed DataFrame to Elastic Cloud using API key

def upload_to_elastic(df, index_name: str = ES_INDEX):
    """Upload parsed logs to Elastic Cloud index."""
    if df.empty:
        st.warning("No data to upload.")
        return

    # Optional: recreate index
    requests.delete(f"{ES_BASE}/{index_name}", headers=HEADERS, verify=True)
    requests.put(
        f"{ES_BASE}/{index_name}",
        json={"settings": {"number_of_shards": 1, "number_of_replicas": 1}},
        headers={"Authorization": f"ApiKey {ES_API_KEY}"}
    )

    # Build NDJSON bulk payload
    buf = []
    for _, row in df.iterrows():
        doc = {k: str(v) for k, v in row.to_dict().items()}
        buf.append(json.dumps({"index": {"_index": index_name}}))
        buf.append(json.dumps(doc))
    data = "\n".join(buf) + "\n"

    r = requests.post(
        f"{ES_BASE}/{index_name}/_bulk?refresh=wait_for",
        data=data.encode("utf-8"),
        headers=HEADERS,
        verify=True,
        timeout=60,
    )

    if r.status_code < 300:
        st.success(f" Uploaded {len(df)} records to Elastic Cloud index '{index_name}'.")
    else:
        st.error(f" Upload failed: {r.status_code} {r.text[:400]}")



# Simple query helper

def query_elastic(match_all=True, limit=100):
    """Return documents from Elastic Cloud."""
    query = {"size": limit, "query": {"match_all": {}} if match_all else {}}
    r = requests.post(f"{ES_BASE}/{ES_INDEX}/_search", json=query,
                      headers={"Authorization": f"ApiKey {ES_API_KEY}"})
    if r.status_code == 200:
        hits = r.json().get("hits", {}).get("hits", [])
        st.info(f"Retrieved {len(hits)} docs from Elastic Cloud.")
        return [h["_source"] for h in hits]
    else:
        st.error(f" Query failed: {r.status_code} {r.text[:300]}")
        return []
