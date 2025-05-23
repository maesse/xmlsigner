from lxml import etree
from copy import deepcopy
import glob
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (padding, utils)
import hashlib
import base64

samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../samples"))
input_files = glob.glob(os.path.join(samples_dir, "*.xml"))

#input_files = ["C:\\Users\\madsl\\OneDrive\\Documents\\xmlsigner\\src\\main\\resources\\xades-detached.xml"]
#input_file = "C:\\Users\\madsl\\OneDrive\\Documents\\xmlsigner\\src\\main\\resources\\signedprops.xml"

# Define namespaces used in the document
namespaces = {
    'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
    'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
    'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
    'xades': 'http://uri.etsi.org/01903/v1.3.2#'
}

# Define namespaces used in the xades Reference
namespaces2 = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'xades': 'http://uri.etsi.org/01903/v1.3.2#'
}

for input_file in input_files:
    # Load and parse XML
    print("Parsing XML file: " + input_file)
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(input_file, parser)
    root = tree.getroot()

    #
    # The xades Reference check is supposed to be done like this:
    # 1. Get the Reference node, which always has a URI attribute='#id-xades-signed-props'
    # 2. Get the xades:SignedProperties referenced by the URI
    # 3. Canonicalize the referenced node (c14n exclusive no comments)
    # 4. Compute the sha256 digest of the canonicalized node and base64 encode it
    # 5. Compare the computed digest with the one in the Reference
    # 6. If they match, the signature is valid
    #

    # Issues found:
    # * None of the xades digests match the expected ones in the samples provided by malaysia
    # * They are also using the wrong Type attribute in the Reference node
    # * * This is the expected value for XAdES: http://uri.etsi.org/01903#SignedProperties
    # * * This is the value found in the official samples: http://www.w3.org/2000/09/xmldsig#SignatureProperties
    # * The official signature documentation is confusing 
    #    * From: https://sdk.myinvois.hasil.gov.my/signature-creation/#step-7-generate-signed-properties-hash
    #       1. Get the properties tag only using the XPath (/Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties)
    #       2. Linearize the XML block (properties tag) and remove the spaces
    #       3. Hash the property tag using SHA-256.
    #       4. Encode the hashed property tag using Base64 Encoder
    #       5. The value generated would be the property named PropsDigest
    #
    #   Step 2 is confusing. This *could* imply c14n, but it doesn't say so. Linearize could mean removing all (non-text) whitespace (minify).
    #       c14n would expand self-closing tags and set namespace values (and possibly more). Linearize would imply a simpler process.
    #   Other steps are clear.
    #
    #   So far, no combination of c14n and minify has produced a valid xades digest.
    #
    #  * The steps documented in the official signature documentation are not correct or have possible security flaws:
    #     * The final signedValue is calculated without taking the xades digest into account (!)
    #     * Since the signature doesn't contain the xades:SignedProperties, as a minimum you could spoof the signature timestamp
    #     * At worst you could spoof the entire signature
    #
    #  * To verify if this is actually how the signature is created, we need to verify the signature against the ds:SignedInfo before the xades:SignedProperties Reference is added

    expectedDocDigest = root.xpath("//ds:Reference/ds:DigestValue", namespaces=namespaces2)[0].text

    #xadesReference = root.xpath("//ds:Reference[@Type='http://uri.etsi.org/01903#SignedProperties']", namespaces=namespaces2)[0]
    reference_results = root.xpath("//ds:Reference[@URI='#id-xades-signed-props']", namespaces=namespaces2)
    if len(reference_results) == 0:
        print("No xades Reference found")
        continue
    elif len(reference_results) > 1:
        print("Multiple xades References found")
        continue

    reference_xades = reference_results[0]

    expectedXadesDigest = reference_xades.xpath("ds:DigestValue", namespaces=namespaces2)[0].text
    print("Xades digest expected:", expectedXadesDigest)

    uri = reference_xades.get("URI")
    uri = uri[1:]  # Remove the leading '#' character
    xadesNode = root.xpath(f"//xades:SignedProperties[@Id='{uri}']", namespaces=namespaces2)[0]

    xadesNode_clean = etree.Element("wrapper")
    xadesNode_clean.append(deepcopy(xadesNode))
    etree.cleanup_namespaces(xadesNode_clean)
    xadesNode_clean = xadesNode_clean[0]

    # cannonicalize
    xadesNode_c14n = etree.tostring(xadesNode, method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=['xades', 'ds'])
    #xadesNode_c14n = etree.tostring(xadesNode_clean, encoding="unicode").encode('utf-8')
    # xadesNode_clean_c14n = etree.tostring(xadesNode_clean, method="c14n", exclusive=True, with_comments=False)

    # sha256 and base64 encode
    xadesDigest = base64.b64encode(hashlib.sha256(xadesNode_c14n).digest()).decode()
    # xades_cleanDigest = base64.b64encode(hashlib.sha256(xadesNode_clean_c14n).digest()).decode()

    print("Xades digest computed:", xadesDigest)
    # print("Xades digest computed:", xades_cleanDigest)

    if xadesDigest != expectedXadesDigest:
        print("Xades digest mismatch 🔒❌")
    else:
        print("Xades digest match 🔒✔️")

    print(xadesNode_c14n)

    #
    # How the main document digest is computed:
    # 1. Get the root document node.
    # 2. Remove all UBLExtensions and cac:Signature nodes
    # 3. Canonicalize the document using the following standard: https://www.w3.org/TR/xml-c14n11/
    # 4. Compute the sha256 digest of the canonicalized document and base64 encode it
    # 5. Compare the computed digest with the one in the Reference
    # 6. If they match, the signature is valid
    #

    # Issues found:
    # * Transforms in the Reference nodes does not appear to be valid. Validators that use the supplied XPath are likely to fail.
    #     * It could have been a problem with the XPath parsers I tried, but I don't think so.
    #     * Instead of using the transforms, I just remove the UBLExtensions and cac:Signature nodes manually.
    #     * To be fair the documentation mentions doing it manually, but it breaks many validators.
    # * The Transform in the sample files also reference the exclusive c14n method: http://www.w3.org/2001/10/xml-exc-c14n#
    #     * This fails, and trying to set exclusive=True in the c14n method doesn't produce a valid digest
    #
    # Basically: completely ignore the transforms mentioned in the document and sample files.

    docRoot = deepcopy(root)

    # Remove all UBLExtensions and cac:Signature nodes
    for tag in ["ext:UBLExtensions", "cac:Signature"]:
        for reference_xades in docRoot.xpath(f"//{tag}", namespaces=namespaces):
            parent = reference_xades.getparent()
            if parent is not None:
                parent.remove(reference_xades)


    # Canonicalize (Technically incorrect since it's not using c14n11, but seems to work ok?)
    c14n_output = etree.tostring(docRoot, method="c14n", exclusive=False, with_comments=False)

    ##print(c14n_output)
    # Output result
    #with open("canonicalized.xml", "wb") as f:
    #    f.write(c14n_output)

    # Compute SHA-256 hash
    sha256_hash = hashlib.sha256(c14n_output).digest()
    sha256_base64 = base64.b64encode(sha256_hash).decode()

    print("Expected document digest: " + expectedDocDigest)
    print("Computed document digest: " + sha256_base64)

    if expectedDocDigest != sha256_base64:
        print("Document digest mismatch 📄❌")
    else:
        print("Document digest match 📄✔️")

    ### Verify the signature

    # How it's supposed to be done:
    # 1. Get the <ds:SignedInfo> node
    # 2. Canonicalize the <ds:SignedInfo> node using the same method as in <CanonicalizationMethod>
    # 3. Get the <ds:SignatureValue> node and decode it from base64
    # 4. Get the <ds:X509Certificate> node and decode it from base64
    # 5. Get the public key from the certificate
    # 6. Verify the signature using the public key, the canonicalized <ds:SignedInfo> node and the <ds:SignatureMethod> algorithm
    # 7. If the signature is valid, the document is valid

    # What is actually done:
    # * Instead of generating a digest from the SignedInfo node, the digest is generated from the entire document (the input to Reference[0]/ds:DigestValue before sha256)

    # Extract <SignedInfo>
    signed_info_node = root.xpath('//ds:SignedInfo', namespaces=namespaces2)[0]

    # Experiment: Remove the xades Reference node (as in: taking the official documentation literally) -- not successful
    # reference_xades = signed_info_node.xpath(f"//ds:Reference", namespaces=namespaces2)[1]
    # parent = reference_xades.getparent()
    # if parent is not None:
    #     parent.remove(reference_xades)

    # Experiment: Overwrite the xades digest value with the computed one -- not successful
    # xadesDigestNode = signed_info_node.xpath(f"//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue", namespaces=namespaces2)[0]
    # xadesDigestNode.text = xadesDigest

    # Canonicalize
    signed_info_c14n = etree.tostring(signed_info_node, method="c14n", exclusive=True)
    

    signature_value_b64 = root.xpath('//ds:SignatureValue', namespaces=namespaces2)[0].text
    signature_bytes = base64.b64decode(signature_value_b64)

    cert_b64 = root.xpath('//ds:X509Certificate', namespaces=namespaces2)[0].text
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    public_key = cert.public_key()

    try:
        public_key.verify(
            signature_bytes,
            # base64.b64decode(expectedDocDigest), # For testing that the signatureValue is valid against the document digest defined in the Reference[0]
            # signed_info_c14n, # How it's supposed to be done (verified against non-malaysia samples)
            sha256_hash,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
    )
        print("✅ Signature is VALID")
    except Exception as e:
        print("❌ Signature is INVALID:", e)

    print("--------------------------------------------------")

