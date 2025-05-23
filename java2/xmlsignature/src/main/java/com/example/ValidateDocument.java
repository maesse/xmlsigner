package com.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class ValidateDocument 
{
    public static void main( String[] args ) throws Exception
    {
        Init.init();
        System.out.println("Working dir: " + System.getProperty("user.dir"));

        // Load a sample
        Path path = Paths.get("../../samples/1.1-Credit-Note-Sample.xml");

        System.out.println("Validating document file: " + path);
        String content = Files.readString(path);

        // Parse XML document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));

        // Get the root element
        Element element = doc.getDocumentElement();
        
        // Generate digest of the main document
        String documentDigest = getDocumentDigest(element, false);
        System.out.println("Generated document digest: " + documentDigest);

        // Generate digest of the xades:SignedProperties tag
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
    private static String getDocumentDigest(Element rootNode, boolean printCanonical) throws Exception {
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
            System.err.println("No Signature tag found!");
        }

        removeWhitespaceNodes(rootElement);

        // Canonicalize
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        canon.canonicalizeSubtree(rootElement, bos);
        byte[] canonicalBytes = bos.toByteArray();

        if(printCanonical) {
            String canonicalXml = new String(canonicalBytes, StandardCharsets.UTF_8);
            System.out.println(canonicalXml);
        }

        return sha256Base64(canonicalBytes);
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
