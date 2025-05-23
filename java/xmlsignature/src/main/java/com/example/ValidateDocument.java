package com.example;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.stream.Stream;

import javax.xml.parsers.*;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.*;
import org.w3c.dom.*;

import com.example.SignHelper.DigestResult;

/**
 * Validates a signed XML document after this e-invoicing standard: https://sdk.myinvois.hasil.gov.my/signature-creation/
 */
public class ValidateDocument 
{
    

    public static void main( String[] args ) throws Exception
    {
        Init.init();
        System.out.println("Working dir: " + System.getProperty("user.dir"));

        // Load a sample
        //Path path = Paths.get("../../samples/1.1-Credit-Note-Sample.xml");
        //Path path = Paths.get("../../samples/signatureOutput.xml");
        //

        Path folderPath = Paths.get("../../samples");

        try (Stream<Path> paths = Files.walk(folderPath)) {
            paths
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".xml"))
                .forEach(path -> {
                    System.out.println("Validating: " + path.getFileName());
                    try {
                        byte[] fileContents = Files.readAllBytes(path);
                        validateDocument(fileContents);
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    
                });
        }
    }

    private static void validateDocument(byte[] fileContents) throws Exception
    {
        // Parse XML document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(fileContents));

        // Get the root element
        Element element = doc.getDocumentElement();

        // Read the expected digest values
        NodeList digestValueList = element.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "DigestValue");
        if(digestValueList.getLength() != 3) {
            throw new IllegalArgumentException("Expected 3 DigestValue, got: " + digestValueList.getLength());
        }

        String expectedDocumentDigest = digestValueList.item(0).getTextContent();
        String expectedSignedPropsDigest = digestValueList.item(1).getTextContent();
        String expectedCertificateDigest = digestValueList.item(2).getTextContent();
        
        // Generate digest of the main document
        DigestResult documentDigest = SignHelper.getDocumentDigest(element, false);
        boolean isDigestMatching = documentDigest.digestValue.equals(expectedDocumentDigest);
        System.out.print(isDigestMatching ? "OK   ":"FAIL ");
        System.out.println("Document digest: " + documentDigest.digestValue);
        if(!isDigestMatching) {
            System.out.println("Expected digest: " + expectedDocumentDigest);
        }

        // Generate digest of the certificate
        String certificateDigest = getCertificateDigest(element);
        isDigestMatching = certificateDigest.equals(expectedCertificateDigest);
        System.out.print(isDigestMatching ? "OK   ":"FAIL ");
        System.out.println("Certificate digest: " + certificateDigest);
        if(!isDigestMatching) {
            System.out.println("Expected digest: " + expectedCertificateDigest);
        }

        // Generate digest of the xades:SignedProperties tag
        NodeList nodes = element.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
        if(nodes.getLength() != 1) throw new IllegalArgumentException("Expected 1 SignedProperties tag, got: " + nodes.getLength());

        // Get the node and clone it because we will be modifying it
        
        
        String signedPropsDigest = SignHelper.getSignedPropsDigest((Element) nodes.item(0), false);
        isDigestMatching = signedPropsDigest.equals(expectedSignedPropsDigest);
        System.out.print(isDigestMatching ? "OK   ":"FAIL ");
        System.out.println("SignedProperties digest: " + signedPropsDigest);
        if(!isDigestMatching) {
            System.out.println("     Expected digest: " + expectedSignedPropsDigest);
        }

        // Check that the signature matches
        if(checkSignature(element, documentDigest.digestSource)) {
            System.out.println("OK   Signature valid");
        } else {
            System.out.println("FAIL Signature check failed!");
        }
    }

    private static boolean checkSignature(Element rootElement, byte[] digestValue) throws Exception {
        // Get SignatureValue value
        NodeList signatureValues = rootElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        if(signatureValues.getLength() != 1) throw new IllegalArgumentException("Expected 1 SignatureValue, got: " + signatureValues.getLength());
        String signatureBase64 = signatureValues.item(0).getTextContent();
        byte[] signatureValue = Base64.getDecoder().decode(signatureBase64);
        
        // Get X509Certificate value
        NodeList certificates = rootElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if(certificates.getLength() != 1) throw new IllegalArgumentException("Expected 1 X509Certificate, got: " + certificates.getLength());
        String certificateBase64 = certificates.item(0).getTextContent();
        byte[] certificateValue = Base64.getDecoder().decode(certificateBase64);

        // Load the X509 certificate from DER bytes
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateValue));

        // Get public key from certificate
        PublicKey publicKey = cert.getPublicKey();

        // Initialize Signature verifier for SHA256withRSA and PKCS#1 v1.5 padding
        Signature sig = Signature.getInstance("SHA256withRSA");

        // Load the key
        sig.initVerify(publicKey);

        // Load the data to verify
        sig.update(digestValue);

        // Verify using the signature
        return sig.verify(signatureValue);
    }

    

    private static String getCertificateDigest(Element rootNode) throws Exception {
        NodeList results = rootNode.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");

        if(results.getLength() != 1) throw new IllegalArgumentException("Expected one certificate, got: " + results.getLength());

        // Get certificate encoded in base64
        String certificateString = results.item(0).getTextContent();

        // Decode base64
        byte[] rawCertificate = Base64.getDecoder().decode(certificateString);

        // Hash it and base64 encode it
        return SignHelper.sha256Base64(rawCertificate);
    }



    
}
