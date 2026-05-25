# Student Guide: Cybersecurity Engineering Lab

## 1. Environment Management

Using a Virtual Environment (`venv`) is required to isolate your lab dependencies. This prevents conflicts and ensures the `pytest` suite runs correctly.

### **Pre-Check: Is `venv` missing?**

While `venv` is pre-installed on **ECS machines**, you may need to install it on personal Linux setups:

* **Ubuntu/Debian/Kali:** `sudo apt update && sudo apt install python3-venv`
* **Fedora:** `sudo dnf install python3-venv`

---

### **Step 1: Activation (Start Here)**

You must activate the environment **every time** you open a new terminal window to work on the lab.

**Linux / macOS / ECS Machines:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

**Windows (PowerShell):**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

```

> **How to tell it's working:** Your terminal prompt will be prefixed with **`(.venv)`**.

---

### **Step 2: Deactivation (When Finished)**

To return your terminal to its normal state, simply run:

```bash
deactivate

```

**Crucial:** Always `deactivate` before switching to other projects or closing your session to ensure your system path remains clean.

---

## 2. Project Resources & Files

### **Files to Edit**

* **`app/client.py`**: Tasks 0, 1, 2, 3, 4, 6, 7, 8
* **`app/resource.py`**: Tasks 0, 5

> **DO NOT EDIT:** `tests/` or `app/oauth.py`. These are used for automated marking.

### **Support Documents**

* **`SECURITY_BEST_PRACTICES.md`**: Explains the logic and "why" of each fix.
* **`LIBRARY_REFERENCE.md`**: Technical API syntax for `PyJWT`, `Flask`, etc.

---

## 3. Marking Criteria (100 Marks)

Your grade is calculated by passing **Security Tests** without breaking existing **Regression Tests**.

| Task | Marks | Focus Area |
| --- | --- | --- |
| **0** | 20 | **Happy Path**: Core authentication functionality. |
| **1** | 10 | **alg:none**: Signature algorithm validation. |
| **2** | 10 | **Audience**: Client ID validation in JWT. |
| **3** | 10 | **Nonce**: Replay attack mitigation. |
| **4** | 10 | **State**: CSRF protection logic. |
| **5** | 10 | **Scope**: Resource Server access control. |
| **6** | 10 | **PKCE Verifier**: Code verifier implementation. |
| **7** | 10 | **PKCE S256**: SHA-256 challenge transformation. |
| **8** | 10 | **Open Redirect**: URL sanitization. |

---

## 4. Testing

With your **`(.venv)`** active, run:

* **Complete Audit:** `pytest`
* **Specific Task:** `pytest tests/test_scope.py`
* **Specific Test:** `pytest -k test_wrong_aud_rejected`