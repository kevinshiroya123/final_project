import os
import subprocess
import time
import requests
import plotly.express as px

#  PATH CONFIGURATION 
venv_path = "/Users/sls-kjs/Desktop/project/masters/code/secority onion/.venv"
python_exec = os.path.join(venv_path, "bin", "python")
app_path = "/Users/sls-kjs/Desktop/project/masters/code/secority onion/openai_model_code/security_onion_gui.py"

# Path to your Elasticsearch binary (adjust version if needed)
es_path = "/usr/local/Cellar/elasticsearch-full/7.17.4/bin/elasticsearch"
# If you are on Intel Mac, use:
# es_path = "/usr/local/Cellar/elasticsearch-full/7.17.4/bin/elasticsearch"

# FUNCTIONS

def is_elasticsearch_running():
    """Check if Elasticsearch is already listening on localhost:9200"""
    try:
        r = requests.get("http://localhost:9200", timeout=2)
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False


def start_elasticsearch():
    """Start Elasticsearch if it's not already running"""
    if not os.path.exists(es_path):
        print(" Elasticsearch binary not found! Please verify the installation path.")
        return None

    print(" Starting Elasticsearch...")
    # Start Elasticsearch in a background process
    process = subprocess.Popen([es_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait until it's up
    for _ in range(30):
        if is_elasticsearch_running():
            print(" Elasticsearch is running on http://localhost:9200")
            return process
        time.sleep(2)

    print(" Warning: Elasticsearch did not respond within 60 seconds.")
    return process


def run_streamlit_app():
    """Run the Streamlit app using the venv's Python"""
    if not os.path.exists(python_exec):
        print(" Virtual environment not found.")
        return
    if not os.path.exists(app_path):
        print(" Streamlit app not found.")
        return

    print(" Running Streamlit app using virtual environment...")
    subprocess.run([python_exec, "-m", "streamlit", "run", app_path])


#  MAIN EXECUTION 
if __name__ == "__main__":
    # 1) Ensure Elasticsearch is running
    es_proc = None
    if not is_elasticsearch_running():
        es_proc = start_elasticsearch()
    else:
        print(" Elasticsearch is already running.")

    # 2) Launch Streamlit
    run_streamlit_app()

    # 3) Optionally, stop ES after Streamlit exits (uncomment if desired)
    # if es_proc:
    #     print(" Stopping Elasticsearch...")
    #     es_proc.terminate()
