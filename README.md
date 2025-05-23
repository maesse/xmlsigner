# 🇲🇾 Malaysian e-Invoicing Digest Verifier

This is a personal project to explore, verify, and sign digital signatures used in Malaysia’s e-Invoicing system, as described in publicly available documentation from LHDN (Lembaga Hasil Dalam Negeri Malaysia).

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
- Signs documents using the Malaysian e-Invoice XML signature flow
- Helps understand how Malaysia's digital signing scheme works (from a technical perspective)

---

## 📁 Project Structure & Implementation Notes

- **java/**: Main implementation for parsing, verifying, and signing e-Invoice XMLs. Most complete and accurate.
- **python/**: Incomplete; does not calculate the SignedProperties digest correctly.
- **csharp/**: Only calculates the xades:SignedProperties digest for reference/testing.
- The python and C# code was part of the exploration phase. The java code combines all the learnings into a working implementation.

---

## 📚 Resources Used

- Official LHDN documentation (XML schema, signature samples)
- XML Signature (XMLDSIG) specification
- Publicly available examples from [https://einvoice.hasil.gov.my](https://einvoice.hasil.gov.my)

---

## ⚡ Quirks & Surprises

- Canonicalization and whitespace handling are critical -— minor differences break signature validation.
- The order of XML elements and attributes must match exactly as in the sample signatures. (Unverified how strict the API with this)
- Digest calculation for xades:SignedProperties is especially sensitive as it doesn't follow normal canonicalization procedures, instead relying on internal Microsoft XML serialization implementation.
- The way the LHDN made the implementation means that essentially no existing tool will correctly validate a signed XML nor will it be able to create a validly signed XML.
- The signature is calculated not on the full SignedInfo tag data but only on the hash of the document (excluding signature tags), meaning that the SignedProperties is _not_ guaranteed to be unchanged.

---

## 🛠️ Tech Stack

- Python 3.x for generating document digest and verifying signature
- C# for generating xades:SignedProperties digest
- Java for full signing and verification implementation

---

### ☕ Java (Signing & Verifying)

The Java implementation is inside `java/xmlsignature`. There is no single entrypoint; instead, two files have `main` methods:

- `com.example.ValidateDocument` — for verifying signed XML documents
- `com.example.SignDocument` — for signing a single document

To run either, use Maven from the `java/xmlsignature` directory. For example:

```bash
cd java/xmlsignature
# To run the verifier:
mvn compile exec:java -Dexec.mainClass="com.example.ValidateDocument"

# To run the signer:
mvn compile exec:java -Dexec.mainClass="com.example.SignDocument"
```

You may need to adjust file paths or arguments as needed for your environment.

---

## 🚀 Running the other experiments

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
