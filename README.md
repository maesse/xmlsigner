# 🇲🇾 Malaysian Myinvois e-Invoicing XML Signer & Verifier

This is a personal project to explore, verify, and sign digital signatures used in Malaysia’s e-Invoicing system, as described in publicly available documentation from LHDNM (Lembaga Hasil Dalam Negeri Malaysia).

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
- **python/**: Incomplete; does not calculate the xades:SignedProperties digest correctly. Contains quite a few notes about the signature process.
- **csharp/**: Only calculates the xades:SignedProperties digest for reference/testing.
- The python and C# code was part of the exploration phase. The java code combines all the learnings into a working implementation.

---

## 📚 Resources Used

- Official LHDN documentation ([Main signature page](https://sdk.myinvois.hasil.gov.my/signature/), [signature samples](https://sdk.myinvois.hasil.gov.my/sample/), [signature creation details](https://sdk.myinvois.hasil.gov.my/signature-creation/))
- XML Signature (XMLDSIG) specification

---

## ⚡ Quirks & Surprises

- Canonicalization and whitespace handling are critical -— minor differences break signature validation.
- The way the LHDN made the implementation means that essentially no existing tool will correctly validate a signed XML nor will it be able to create a validly signed XML.
- The MS XML handling was not at all obvious, but the use of Powershell and .net libraries in the [JSON documentation](https://sdk.myinvois.hasil.gov.my/files/Digital_Signature_User_Guide.pdf) gave a clue.
- Digest calculation for `xades:SignedProperties` is especially sensitive as it doesn't follow normal canonicalization procedures, instead relying on internal Microsoft XML serialization implementation. Verify that your input to the sha256 function satisfies these conditions:
  - Self-closing tags are used where applicable (It's only `<ds:DigestMethod>`), which means you can't use canonicalization, or alternatively you can patch up `ds:DigestMethod` with a string.replace. There _must_ be a whitespace before the self-closing tag: ` />`
  - XML must me minified (removing extra whitespace and newlines).
  - namespace attribute (`xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"`) must be present on `xades:SignedProperties`, and it must be the last attribute in the tag.
  - namespace attribute (`xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`) must be present on all `ds:` tags, and it must be the last attribute in the tag.
  - look at `output/cs-test-output.txt` for an example
- Generating the document digest source: The XML needs to be minified as well (extra whitespace and line breaks should be removed)
- The signature value is not calculated after the XAdES/XMLDSIG standard, which would be `privatekey.sign(c14n(ds:SignedInfo))`. Instead its: `privateKey.sign(documentDigestSource)`.

---

## 🛠️ Tech Stack

- Python 3.x for generating document digest and verifying signature
- C# for generating xades:SignedProperties digest
- Java (1.8 compatible) for full signing and verification implementation

---

## ☕ Java (Signing & Verifying)

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

---

## License

This project is licensed under the [MIT License](LICENSE).
