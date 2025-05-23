package com.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.*;




public class SignHelper {

    public static class DigestResult {
        public DigestResult(byte[] digestSource) throws Exception {
            this.digestSource = digestSource;
            this.digestValue = SignHelper.sha256Base64(digestSource);
        }
        byte[] digestSource;
        String digestValue; // digestSource after sha256 and base64 encoding
    }

    /**
     * Procedure is as follows:
     * 1. Remove all UBLExtensions and Reference elements
     * 2. (undocumented) Remove unnecessary newlines and whitespace aka linearize
     * 3. Run c14n11 (non-exclusive) canonicalization
     * 4. Sha256 the resulting bytes
     * 5. Base64 encode the sha256 hash
     * @param element root document node
     * @param printCanonical
     * @return Base64 encoded digest
     * @throws InvalidCanonicalizerException
     * @throws CanonicalizationException
     */
    public static DigestResult getDocumentDigest(Element rootNode, boolean printCanonical) throws Exception {
        // Make a clone of the root node so later stages won't be impacted
        Element rootElement = (Element) rootNode.cloneNode(true);

        // Remove UBLExtensions
        NodeList list = rootElement.getElementsByTagNameNS("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2","UBLExtensions");
        if(list.getLength() == 1) {
            rootElement.removeChild(list.item(0));
        } else {
            System.err.println("No UBLExtensions tag found!");
        }

        // Remove cac:Signature
        list = rootElement.getElementsByTagNameNS("urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2", "Signature");
        if(list.getLength() == 1) {
            rootElement.removeChild(list.item(0));
        } else {
            System.err.println("No cac:Signature tag found!");
        }

        removeWhitespaceNodes(rootElement);

        // Canonicalize
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
        byte[] canonicalBytes = canon.canonicalizeSubtree(rootElement);

        if(printCanonical) {
            String canonicalXml = new String(canonicalBytes, StandardCharsets.UTF_8);
            System.out.println(canonicalXml);
        }

        return new DigestResult(canonicalBytes);
    }

    /**
     * Generated the digest from the SignedProperties tag, based on custom behavior
     * @param rootNode
     * @param printCanonical
     * @return
     * @throws Exception
     */
    public static String getSignedPropsDigest(Element rootNode, boolean printCanonical) throws Exception {
        // NodeList nodes = rootNode.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
        // if(nodes.getLength() != 1) throw new IllegalArgumentException("Expected 1 SignedProperties tag, got: " + nodes.getLength());

        // Get the node and clone it because we will be modifying it
        Element signedPropertiesNode = (Element)rootNode.cloneNode(true);

        // Remove whitespace / minify the node
        removeWhitespaceNodes(signedPropertiesNode);

        // Canonicalize 
        // Note that this is not what the LHDNM describes in their documentation.
        // But doing a c14n-excl gets the result pretty close, the rest is patched up.
        // Their implementation are relying on Microsoft XML internal serializer behavior and formatting quirks.
        signedPropertiesNode.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
        signedPropertiesNode.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        String canonicalXml = new String(canon.canonicalizeSubtree(signedPropertiesNode), StandardCharsets.UTF_8);

        // Emulate Microsoft XML attribute ordering
        canonicalXml = moveNamespaceLast(canonicalXml);

        // Redo self-closing tag after c14n
        canonicalXml = canonicalXml.replace("></ds:DigestMethod>", " />"); // Note that MS XML puts a space before the self-closing /

        if(printCanonical) {
            System.out.println(canonicalXml);
        }

        return sha256Base64(canonicalXml.getBytes(StandardCharsets.UTF_8));
    }

    public static String moveNamespaceLast(String xml) {
        // Microsoft XML serializer puts the namespace attribute last (in the valid examples)
        // These two tags are manually patched up
        
        // For xades:SignedProperties
        xml = xml.replaceAll(
            "(<xades:SignedProperties)\\s+(xmlns:xades=\"[^\"]+\")\\s+(Id=\"[^\"]+\")",
            "$1 $3 $2"
        );
        
        // For ds:DigestMethod
        xml = xml.replaceAll(
            "(<ds:DigestMethod)\\s+(xmlns:ds=\"[^\"]+\")\\s+(Algorithm=\"[^\"]+\")",
            "$1 $3 $2"
        );
        
        return xml;
    }

    public static String sha256Base64(byte[] inputBytes) throws Exception {
        // 1. Hash the input
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(inputBytes);

        // 2. Base64-encode the result
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    public static void removeWhitespaceNodes(Node node) {
        NodeList children = node.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                if (child.getTextContent().trim().isEmpty()) {
                    node.removeChild(child);
                }
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                removeWhitespaceNodes(child);
            }
        }
    }
}
