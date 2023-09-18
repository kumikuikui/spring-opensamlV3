package com.ssm.mpsi.SAMLProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
// import java.time.Duration;
// import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class SAMLRequest {

        public static final String MESSAGE_RECEIVER_ENDPOINT = "http://localhost:8080/IDPsamlRes";
        private static final String ASSERTION_CONSUMER_ENDPOINT = "";
        private static final String ISSUER = "https://imesdev.ssm4u.com.my/saml/samlMetadata";
        private static final String KEY_STORE_PASSWORD = "password";
        private static final String KEY_STORE_ENTRY_PASSWORD = "password";
        private static final String KEY_STORE_PATH = "/senderKeystore.jks";
        private static final String ENTITY_ID = "sender.example.com";

        public AuthnRequest buildAuthnRequest() {
                AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
                authnRequest.setIssueInstant(DateTime.now());
                authnRequest.setDestination(MESSAGE_RECEIVER_ENDPOINT);
                authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
                authnRequest.setAssertionConsumerServiceURL(ASSERTION_CONSUMER_ENDPOINT);
                authnRequest.setID("IMES_" + OpenSAMLUtils.generateSecureRandomId());
                authnRequest.setIssuer(buildIssuer());
                authnRequest.setNameIDPolicy(buildNameIdPolicy());
                authnRequest.setForceAuthn(false);
                authnRequest.setIsPassive(false);

                return authnRequest;
        }

        private NameIDPolicy buildNameIdPolicy() {
                NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
                nameIDPolicy.setAllowCreate(true);

                nameIDPolicy.setFormat(NameIDType.TRANSIENT);

                return nameIDPolicy;
        }

        private Issuer buildIssuer() {
                Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
                issuer.setValue(ISSUER);

                return issuer;
        }

        private KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
                try {
                        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                        InputStream inputStream = this.getClass().getResourceAsStream(pathToKeyStore);
                        keystore.load(inputStream, keyStorePassword.toCharArray());
                        inputStream.close();
                        return keystore;
                } catch (Exception e) {
                        throw new RuntimeException("Something went wrong reading keystore", e);
                }
        }

        public Credential getSenderSigningCredential() throws Exception {
                // Get key store
                KeyStore keystore = readKeystoreFromFile(KEY_STORE_PATH, KEY_STORE_PASSWORD);
                Map<String, String> passwordMap = new HashMap<String, String>();
                passwordMap.put(ENTITY_ID, KEY_STORE_ENTRY_PASSWORD);

                // Create key store resolver
                KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

                // Set criterion to get relevant certificate
                Criterion criterion = new EntityIdCriterion(ENTITY_ID);
                CriteriaSet criteriaSet = new CriteriaSet();
                criteriaSet.add(criterion);

                // Resolve credential
                return resolver.resolveSingle(criteriaSet);
        }

        public SignatureSigningParameters buildSignatureSigningParameters() throws Exception {
                SignatureSigningParameters signingParameters = new SignatureSigningParameters();
                signingParameters.setSigningCredential(getSenderSigningCredential());
                signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
                signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
                signingParameters.setSignatureCanonicalizationAlgorithm(
                                SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
                return signingParameters;
        }

        public static Endpoint URLToEndpoint(String URL) {
                SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
                endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                endpoint.setLocation(URL);

                return endpoint;
        }
}
