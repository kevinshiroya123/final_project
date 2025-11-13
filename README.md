# 🚀 Quick Start — Security Onion Log Analyzer

### 1️⃣ Clone the repository

```bash
git clone https://github.com/kevinshiroya123/final_project.git
cd final_project/openai_model_code
```

### 2️⃣ Create `.env` with your OpenAI key

```bash
echo "OPENAI_API_KEY=sk-proj-your_real_api_key_here" > .env
```

### 3️⃣ Create environment & install dependencies

```bash
conda env create -f run_security_onion.yml
conda activate security-onion-llm
```

*(Or manually:)*

```bash
pip install streamlit openai requests python-dotenv pandas plotly seaborn matplotlib
```

### 4️⃣ Run the application

```bash
python run_app.py
```

### 5️⃣ Open your browser

Visit 👉 **[http://localhost:8501](http://localhost:8501)**
