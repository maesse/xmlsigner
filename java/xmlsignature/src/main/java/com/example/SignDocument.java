package com.example;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xml.security.Init;
import org.w3c.dom.*;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


import com.example.SignHelper.DigestResult;


public class SignDocument {
    final static String NS_EXT = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
    final static String NS_SIG = "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2";
    final static String NS_SAC = "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2";
    final static String NS_SBC = "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2";
    final static String NS_CBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
    final static String NS_CAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
    final static String NS_DS = "http://www.w3.org/2000/09/xmldsig#";
    final static String NS_XADES = "http://uri.etsi.org/01903/v1.3.2#";

    public static class ElementBindings {
        Element documentDigestValue;
        Element signedPropsDigestValue;
        Element signatureValue;
        Element x509Certificate;
        Element signedProperties;
        Element signingTime;
        Element certDigestValue;
        Element x509IssuerName;
        Element x509SerialNumber;
        public ElementBindings() {}
    }

    public static void main( String[] args ) throws Exception
    {
        System.setProperty("javax.xml.transform.TransformerFactory", "org.apache.xalan.processor.TransformerFactoryImpl");

        Init.init();
        System.out.println("Working dir: " + System.getProperty("user.dir"));

        // Load a sample
        Path path = Paths.get("../../samples/1.1-Credit-Note-Sample.xml");

        System.out.println("Signing: " + path.getFileName());
        byte[] fileContents = Files.readAllBytes(path);
        Document doc = signDocument(fileContents);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

        DOMSource domSource = new DOMSource(doc);
        //StreamResult result = new StreamResult(System.out);
        StreamResult result = new StreamResult(new File("../../output/signatureOutput.xml"));
        transformer.transform(domSource, result);
    }

    private static String signData(String privateKeyPath, String password, byte[] dataToSign) throws Exception {
        char[] pwBytes = password.toCharArray();
        FileInputStream keyFile = new FileInputStream(privateKeyPath);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(keyFile, pwBytes);

        String alias = keystore.aliases().nextElement();
        
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, pwBytes);
        keyFile.close();

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(dataToSign);

        byte[] signatureBytes = signer.sign();
        String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);
        return base64Signature;
    }

    private static Document signDocument(byte[] fileContents) throws Exception
    {
        // Parse XML document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(fileContents));

        // Get the root element
        Element element = doc.getDocumentElement();

        // Generate digest of the main document
        DigestResult documentDigest = SignHelper.getDocumentDigest(element, false);
        
        // For testing, clean up the document if it has existing signature tags
        // Remove UBLExtensions
        NodeList list = element.getElementsByTagNameNS("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2","UBLExtensions");
        if(list.getLength() == 1) {
            element.removeChild(list.item(0));
        }

        // Remove cac:Signature
        list = element.getElementsByTagNameNS("urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2", "Signature");
        if(list.getLength() == 1) {
            element.removeChild(list.item(0));
        }

        ElementBindings bindings = buildStructure(doc);
        
        // document digest
        bindings.documentDigestValue.setTextContent(documentDigest.digestValue);

        // certificate
        X509Certificate cert = getPublicKey("../../cert/myinvois.crt");
        byte[] publicKeyBytes = cert.getEncoded();
        bindings.x509Certificate.setTextContent(Base64.getEncoder().encodeToString(publicKeyBytes));
        
        // Hashed certificate key
        bindings.certDigestValue.setTextContent(SignHelper.sha256Base64(publicKeyBytes));

        // Public key serial number
        bindings.x509SerialNumber.setTextContent("" + cert.getSerialNumber());

        // Public key issuer name
        bindings.x509IssuerName.setTextContent(cert.getIssuerDN().getName());

        // Signing time
        bindings.signingTime.setTextContent(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));

        // Sign the document
        bindings.signatureValue.setTextContent(signData("../../cert/myinvois.p12", "secret", documentDigest.digestSource));

        bindings.signedPropsDigestValue.setTextContent(SignHelper.getSignedPropsDigest(bindings.signedProperties, true));

        return doc;
    }

    private static X509Certificate getPublicKey(String certPath) throws Exception {
        FileInputStream fis = new FileInputStream(certPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }


    private static ElementBindings buildStructure(Document doc) {
        ElementBindings bindings = new ElementBindings();

        Element ublExtensions = doc.createElement("UBLExtensions");
        ublExtensions.setAttribute("xmlns", NS_EXT);
        // ublExtensions.setAttribute("xmlns:sig", NS_SIG);
        // ublExtensions.setAttribute("xmlns:sac", NS_SAC);
        // ublExtensions.setAttribute("xmlns:sbc", NS_SBC);
        // ublExtensions.setAttribute("xmlns:cbc", NS_CBC);
        // ublExtensions.setAttribute("xmlns:ds", NS_DS);
        // ublExtensions.setAttribute("xmlns:xades", NS_XADES);
        doc.getFirstChild().insertBefore(ublExtensions, doc.getFirstChild().getChildNodes().item(1));
        //doc.getFirstChild().appendChild(ublExtensions);
        

        // <ext:UBLExtension>
        Element ublExtension = doc.createElement("UBLExtension");
        ublExtensions.appendChild(ublExtension);

        // <ext:ExtensionURI>
        Element extensionURI = doc.createElement("ExtensionURI");
        extensionURI.setTextContent("urn:oasis:names:specification:ubl:dsig:enveloped:xades");
        ublExtension.appendChild(extensionURI);

        // <ext:ExtensionContent>
        Element extensionContent = doc.createElement("ExtensionContent");
        ublExtension.appendChild(extensionContent);

        // <sig:UBLDocumentSignatures>
        Element ublDocSignatures = doc.createElementNS(NS_SIG, "sig:UBLDocumentSignatures");
        ublDocSignatures.setAttribute("xmlns:sig", NS_SIG);
        ublDocSignatures.setAttribute("xmlns:sac", NS_SAC);
        ublDocSignatures.setAttribute("xmlns:sbc", NS_SBC);
        extensionContent.appendChild(ublDocSignatures);

        // <sac:SignatureInformation>
        Element signatureInformation = doc.createElement("sac:SignatureInformation");
        ublDocSignatures.appendChild(signatureInformation);

        // <cbc:ID>
        Element id = doc.createElement("cbc:ID");
        id.setTextContent("urn:oasis:names:specification:ubl:signature:1");
        signatureInformation.appendChild(id);

        // <sbc:ReferencedSignatureID>
        Element refSigID = doc.createElement("sbc:ReferencedSignatureID");
        refSigID.setTextContent("urn:oasis:names:specification:ubl:signature:Invoice");
        signatureInformation.appendChild(refSigID);

        // <ds:Signature>
        Element signature = doc.createElementNS(NS_DS, "ds:Signature");
        signature.setAttribute("Id", "signature");
        signatureInformation.appendChild(signature);

        // <ds:SignedInfo>
        Element signedInfo = doc.createElement("ds:SignedInfo");
        signature.appendChild(signedInfo);

        // <ds:CanonicalizationMethod>
        Element canonicalizationMethod = doc.createElement("ds:CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
        signedInfo.appendChild(canonicalizationMethod);

        // <ds:SignatureMethod>
        Element signatureMethod = doc.createElement("ds:SignatureMethod");
        signatureMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        signedInfo.appendChild(signatureMethod);

        // <ds:Reference>
        Element reference = doc.createElement("ds:Reference");
        reference.setAttribute("Id", "id-doc-signed-data");
        reference.setAttribute("URI", "");
        signedInfo.appendChild(reference);

        // <ds:Transforms>
        Element transforms = doc.createElement("ds:Transforms");
        reference.appendChild(transforms);

        // <ds:Transform>
        Element transform = doc.createElement("ds:Transform");
        transform.setAttribute("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116");
        transforms.appendChild(transform);

        // <ds:XPath>
        Element xpath = doc.createElement("ds:XPath");
        xpath.setTextContent("not(//ancestor-or-self::ext:UBLExtensions)");
        transform.appendChild(xpath);

        // <ds:Transform>
        Element transform2 = doc.createElement("ds:Transform");
        transform2.setAttribute("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116");
        transforms.appendChild(transform2);

        // <ds:XPath>
        Element xpath2 = doc.createElement("ds:XPath");
        xpath2.setTextContent("not(//ancestor-or-self::cac:Signature)");
        transform2.appendChild(xpath2);

        // <ds:Transform>
        Element transform3 = doc.createElement("ds:Transform");
        transform3.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
        transforms.appendChild(transform3);

        // <ds:DigestMethod>
        Element digestMethod = doc.createElement("ds:DigestMethod");
        digestMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        reference.appendChild(digestMethod);

        // <ds:DigestValue>
        Element digestValue = doc.createElement("ds:DigestValue");
        bindings.documentDigestValue = digestValue;
        reference.appendChild(digestValue);

        // <ds:Reference>
        Element reference2 = doc.createElement("ds:Reference");
        reference2.setAttribute("Type", "http://www.w3.org/2000/09/xmldsig#SignatureProperties");
        reference2.setAttribute("URI", "#id-xades-signed-props");
        signedInfo.appendChild(reference2);

        // <ds:DigestMethod>
        Element digestMethod2 = doc.createElement("ds:DigestMethod");
        digestMethod2.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        reference2.appendChild(digestMethod2);

        // <ds:DigestValue>
        Element digestValue2 = doc.createElement("ds:DigestValue");
        bindings.signedPropsDigestValue = digestValue2;
        reference2.appendChild(digestValue2);


        // <ds:SignatureValue>
        Element signatureValue = doc.createElement("ds:SignatureValue");
        bindings.signatureValue = signatureValue;
        signature.appendChild(signatureValue);


        // <ds:KeyInfo>
        Element keyInfo = doc.createElement("ds:KeyInfo");
        signature.appendChild(keyInfo);

        // <ds:X509Data>
        Element x509Data = doc.createElement("ds:X509Data");
        keyInfo.appendChild(x509Data);

        // <ds:X509Certificate>
        Element x509Certificate = doc.createElement("ds:X509Certificate");
        bindings.x509Certificate = x509Certificate;
        x509Data.appendChild(x509Certificate);


        // <ds:Object>
        Element dsObject = doc.createElement("ds:Object");
        signature.appendChild(dsObject);

        // <xades:QualifyingProperties>
        Element qualifyingProperties = doc.createElement("xades:QualifyingProperties");
        qualifyingProperties.setAttribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
        qualifyingProperties.setAttribute("Target", "signature");
        dsObject.appendChild(qualifyingProperties);

        // <xades:SignedProperties>
        Element signedProperties = doc.createElementNS(NS_XADES, "xades:SignedProperties");
        signedProperties.setAttribute("Id", "id-xades-signed-props");
        bindings.signedProperties = signedProperties;
        qualifyingProperties.appendChild(signedProperties);

        // <xades:SignedSignatureProperties>
        Element signedSignatureProperties = doc.createElement("xades:SignedSignatureProperties");
        signedProperties.appendChild(signedSignatureProperties);

        // <xades:SigningTime>
        Element signingTime = doc.createElement("xades:SigningTime");
        bindings.signingTime = signingTime;
        signedSignatureProperties.appendChild(signingTime);

        // <xades:SigningCertificate>
        Element signingCertificate = doc.createElement("xades:SigningCertificate");
        signedSignatureProperties.appendChild(signingCertificate);

        // <xades:Cert>
        Element cert = doc.createElement("xades:Cert");
        signingCertificate.appendChild(cert);

        // <xades:CertDigest>
        Element certDigest = doc.createElement("xades:CertDigest");
        cert.appendChild(certDigest);

        // <ds:DigestMethod>
        Element digestMethod3 = doc.createElementNS(NS_DS, "ds:DigestMethod");
        digestMethod3.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        certDigest.appendChild(digestMethod3);

        // <ds:DigestValue>
        Element digestValue3 = doc.createElementNS(NS_DS, "ds:DigestValue");
        bindings.certDigestValue = digestValue3;
        certDigest.appendChild(digestValue3);

        // <xades:IssuerSerial>
        Element issuerSerial = doc.createElement("xades:IssuerSerial");
        cert.appendChild(issuerSerial);

        // <ds:X509IssuerName>
        Element x509IssuerName = doc.createElementNS(NS_DS, "ds:X509IssuerName");
        bindings.x509IssuerName = x509IssuerName;
        issuerSerial.appendChild(x509IssuerName);

        // <ds:X509SerialNumber>
        Element x509SerialNumber = doc.createElementNS(NS_DS, "ds:X509SerialNumber");
        bindings.x509SerialNumber = x509SerialNumber;
        issuerSerial.appendChild(x509SerialNumber);


        // <cac:Signature>
        Element signature2 = doc.createElement("cac:Signature");
        NodeList siblingList = doc.getElementsByTagNameNS(NS_CAC, "AccountingSupplierParty");
        if(siblingList.getLength() != 1) throw new IllegalArgumentException("Expected cac:AccountingSupplierParty tag in document -- not found");
        siblingList.item(0).getParentNode().insertBefore(signature2, siblingList.item(0));

        // <cbc:ID>
        Element id2 = doc.createElement("cbc:ID");
        id2.setTextContent("urn:oasis:names:specification:ubl:signature:Invoice");
        signature2.appendChild(id2);

        // <cbc:SignatureMethod>
        Element signatureMethod2 = doc.createElement("cbc:SignatureMethod");
        signatureMethod2.setTextContent("urn:oasis:names:specification:ubl:dsig:enveloped:xades");
        signature2.appendChild(signatureMethod2);

        return bindings;
    }
}
