import streamlit as st
from openai import OpenAI
import json
import requests

GPT_MODEL = "gpt-4o-mini"
client = None

# Elasticsearch config

ES_INDEX = "windows-logs"
ES_BASE = "http://localhost:9200"
ES_SEARCH_URL = f"{ES_BASE}/{ES_INDEX}/_search"
ES_SCROLL_URL = f"{ES_BASE}/_search/scroll"
SCROLL_SIZE = 1000  # Number of logs fetched per scroll request
MAX_LOGS = 3000     # Limit logs sent to GPT for context



# Initialize OpenAI

def init_openai(api_key):
    """Initialize the OpenAI client globally."""
    global client
    client = OpenAI(api_key=api_key)



# Fetch all logs from Elasticsearch

def fetch_all_logs_from_elasticsearch() -> list:
    """
    Fetch all documents from Elasticsearch (using scroll API).
    Returns a list of log dicts.
    """
    all_hits = []
    query = {"size": SCROLL_SIZE, "query": {"match_all": {}}}

    try:
        r = requests.post(ES_SEARCH_URL + "?scroll=1m", json=query)
        if r.status_code != 200:
            st.error(f" Elasticsearch query failed: {r.text}")
            return []

        data = r.json()
        scroll_id = data.get("_scroll_id")
        hits = data.get("hits", {}).get("hits", [])
        all_hits.extend(h["_source"] for h in hits)

        while hits and len(all_hits) < MAX_LOGS:
            r_scroll = requests.post(ES_SCROLL_URL, json={"scroll": "1m", "scroll_id": scroll_id})
            data = r_scroll.json()
            hits = data.get("hits", {}).get("hits", [])
            all_hits.extend(h["_source"] for h in hits)
            if not hits:
                break

        st.info(f" Retrieved {len(all_hits)} logs from Elasticsearch for GPT context.")
        return all_hits

    except Exception as e:
        st.error(f" Failed to fetch logs from Elasticsearch: {e}")
        return []



# GPT Summary Generator

def analyze_logs_with_gpt(logs):
    """Analyze logs with GPT and summarize key events."""
    if not client:
        st.error(" OpenAI client not initialized. Call init_openai(api_key) first.")
        return ""

    if not logs:
        st.warning(" No logs available for GPT analysis.")
        return ""

    # Use cache if available
    if "log_summary" in st.session_state and "log_data" in st.session_state:
        st.info(" Using cached GPT analysis (no new tokens).")
        return st.session_state["log_summary"]

    # Convert to text
    text_logs = "\n".join(json.dumps(log, indent=2) for log in logs[:30])

    prompt = f"""
    You are a SOC analyst reviewing Windows Security Event Logs.
    Summarize key findings, suspicious activity, failed logons, or anomalies.

    Logs (sample up to 30):
    {text_logs}

    Provide:
    - Key event types (e.g., logon, process creation, privilege escalation)
    - Systems affected
    - Indicators of compromise or anomalies
    - Recommended next steps
    """

    st.info(" Analyzing logs with GPT...")

    try:
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.4,
        )
        summary = response.choices[0].message.content
    except Exception as e:
        st.error(f" GPT API call failed: {e}")
        return ""

    st.session_state["log_summary"] = summary
    st.session_state["log_data"] = logs
    return summary



# GPT Chatbot (Fetches ALL Logs from Elasticsearch)

def chat_with_logs(key_suffix: str = "main"):
    """
    GPT-powered chat that uses ALL logs from Elasticsearch (not just cached ones).
    """
    if not client:
        st.error(" GPT client not initialized.")
        return

    # Fetch fresh logs from Elasticsearch
    logs = fetch_all_logs_from_elasticsearch()
    if not logs:
        st.warning(" No logs found in Elasticsearch.")
        return

    # Create / restore chat history in session_state

    chat_key = f"chat_history_{key_suffix}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = []

    # Display previous messages
    for sender, message in st.session_state[chat_key]:
        st.chat_message(sender).write(message)

    # Chat input
    user_query = st.chat_input(
        "Ask GPT about your full Elasticsearch logs:",
        key=f"chat_input_{key_suffix}"
    )

    if user_query:
        # Convert logs for GPT context
        context = "\n".join(json.dumps(log, indent=2) for log in logs[:MAX_LOGS])

        system_prompt = (
            "You are a cybersecurity analyst assistant. "
            "Analyze the full Elasticsearch dataset of Windows Security Logs. "
            "Use all provided context to answer precisely, "
            "highlighting suspicious behavior, failed logons, and anomalies."
        )

        prompt = f"""
        Context Logs (sample up to {MAX_LOGS} events):
        {context}

        User Query:
        {user_query}
        """

        # Show user message
        st.chat_message("user").write(user_query)
        st.session_state[chat_key].append(("user", user_query))

        with st.spinner(" GPT analyzing Elasticsearch logs..."):
            try:
                response = client.chat.completions.create(
                    model=GPT_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=800,
                    temperature=0.4,
                )
                answer = response.choices[0].message.content
            except Exception as e:
                answer = f" GPT chat request failed: {e}"

        st.chat_message("assistant").write(answer)
        st.session_state[chat_key].append(("assistant", answer))
