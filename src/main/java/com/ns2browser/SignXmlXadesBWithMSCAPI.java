/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.ns2browser;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters.XPathElementPlacement;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.DSSTransformOutput;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;

import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

/**
 * How to sign using MS-CAPI.
 */
public class SignXmlXadesBWithMSCAPI {

	/**
	 * Executable application
	 */
	private SignXmlXadesBWithMSCAPI() {
	}

	/**
	 * Main method
	 *
	 * @param args not applicable
	 * @throws Exception if an exception occurs
	 */
	public static void main(String[] args) throws Exception {
		try (Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken("myinvois.p12", new PasswordProtection("secret".toCharArray()))) {
			DSSDocument toSignDocument = new FileDocument("src/main/resources/1.1-Invoice-Consolidated-Sample.xml");
			
			// Select the private key entry to use for signing
			List<DSSPrivateKeyEntry> list = signingToken.getKeys();
			System.out.println(list.size());
			DSSPrivateKeyEntry privateKey = list.get(0);
			
			// Preparing parameters for the PAdES signature
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setEn319132(false);
			
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			// We choose the type of the signature packaging (ENVELOPING, DETACHED).
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token.
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
			//parameters.setXPathLocationString("/");
			//parameters.setXPathElementPlacement(XPathElementPlacement.XPathAfter);
			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());
			
			DomUtils.registerNamespace(new DSSNamespace("http://www.w3.org/2000/09/xmldsig#","ds"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2","ext"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2","cac"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2","cbc"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2","sig"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2","sac"));
			DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2","sbc"));
			
			List<DSSReference> references = new ArrayList<>();
			{
				// Initialize and configure ds:Reference based on the provided signer document
				DSSReference dssReference = new DSSReference();
				// Load the document to be signed
				
				dssReference.setContents(toSignDocument);
				dssReference.setId("id-doc-signed-data");
				// Prepare transformations in the proper order
				List<DSSTransform> transforms = new ArrayList<>();
				//DSSNamespace ns = new DSSNamespace("http://www.w3.org/2000/09/xmldsig#", "ds");
				DSSNamespace ext = new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", "ext");
				
				// DSSTransform enveloped1Transform = new XPathTransform("[local-name()='Invoice']//[local-name()='UBLExtensions']");
				// transforms.add(enveloped1Transform);
				// DSSTransform enveloped2Transform = new XPathTransform("[local-name()='Invoice']//[local-name()='Signature']");
				// transforms.add(enveloped2Transform);
				// transforms.add(new EnvelopedSignatureTransform());
				DSSTransform envelopedTransform1 = new XPath2FilterTransform("descendant::ext:UBLExtensions", "subtract");
				transforms.add(envelopedTransform1);
				DSSTransform envelopedTransform2 = new XPath2FilterTransform("descendant::cac:Signature", "subtract");
				transforms.add(envelopedTransform2);
				
				DSSTransform canonicalization = new CanonicalizationTransform(CanonicalizationMethod.INCLUSIVE);
				//System.out.println(new String(XMLCanonicalizer.createInstance(XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD).canonicalize(toSignDocument.openStream())));
				transforms.add(canonicalization);
				dssReference.setTransforms(transforms);
				// set empty URI to cover the whole document
				dssReference.setUri("");
				dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
				references.add(dssReference);
			}

			parameters.setReferences(references);
			
			
			
			
			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create CAdES xadesService for signature
			XAdESService xadesService = new XAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = xadesService.getDataToSign(toSignDocument, parameters);

			System.out.println(new String(dataToSign.getBytes(), java.nio.charset.StandardCharsets.UTF_8));

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = xadesService.signDocument(toSignDocument, parameters, signatureValue);

			// save the signed document on the filesystem
			signedDocument.save("target/signedXmlXades.xml");
		}
	}

}