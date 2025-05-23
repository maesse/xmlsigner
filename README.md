# 🇲🇾 Malaysian e-Invoicing Digest Verifier

This is a personal project to explore and verify the digital signature digest generation process used in Malaysia’s e-Invoicing system, as described in publicly available documentation from LHDN (Lembaga Hasil Dalam Negeri Malaysia).

> ⚠️ **Disclaimer**  
> This project is based entirely on **publicly available documentation** provided by LHDN.  
> It is a personal effort and **not affiliated with, endorsed by, or representative of any employer or organization**.  
> All sample data is synthetic and does not contain real or confidential information.  
> Use this repository at your own risk.

---

## 🧩 What This Does

- Parses sample e-Invoice XML documents
- Recomputes digest values (e.g. SHA256 hashes) for signed components
- Verifies integrity against the expected values provided in the XML
- Helps understand how Malaysia's digital signing scheme works (from a technical perspective)

---

## 📚 Resources Used

- Official LHDN documentation (XML schema, signature samples)
- XML Signature (XMLDSIG) specification
- Publicly available examples from [https://einvoice.hasil.gov.my](https://einvoice.hasil.gov.my)

---

## 🛠️ Tech Stack

- Python 3.x for generating document digest and verifying signature
- C# for generating xades:SignedProperties digest
---

## 🚀 Getting Started

Clone the repository and run:

```bash
cd python
pip install -r requirements.txt
python test.py
```

```bash
cd csharp
dotnet run
```