package com.ssm.mpsi.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ssm.mpsi.SAMLProvider.OpenSAMLUtils;
import com.ssm.mpsi.SAMLProvider.SAMLRequest;
import com.ssm.mpsi.SAMLProvider.IDP.IDPCredentials;
import com.ssm.mpsi.SAMLProvider.IDP.IDPMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

@RestController
public class IDPController {

    public static final String IDP_ENTITY_ID = "TestIDP";
    public static final String SSO_SERVICE = "http://localhost:8080/opensaml4-webprofile-demo/idp/singleSignOnService";
    public static final String ARTIFACT_RESOLUTION_SERVICE = "http://localhost:8080/opensaml4-webprofile-demo/idp/artifactResolutionService";
    private static final String SENDER_ENTITY_ID = "http://localhost:8080";
    private static final String SENDER_METADATA_PATH = "http://localhost:8080/samlMetadata";

    @RequestMapping(value = "/IDPsamlRes", method = RequestMethod.GET)
    void IDPsamlReq(HttpServletResponse httpServletResponse, HttpServletRequest req)
            throws Exception {

        HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setHttpServletRequest(req);

        AuthnRequest authnRequest;
        try {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            decoder.setParserPool(parserPool);
            decoder.initialize();
            decoder.decode();
            MessageContext messageContext = decoder.getMessageContext();
            authnRequest = (AuthnRequest) messageContext.getMessage();
            OpenSAMLUtils.logSAMLObject(authnRequest);
            // System.out.println(req.getParameter("Signature"));
            // verifySignatureUsingMessageHandler(messageContext);
            System.out.println(" ------------------------------------------------------ VERIFIED SUCCESS ---------------------------");

        } catch (MessageDecodingException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        Response artifactResponse = buildArtifactResponse();

        MessageContext context = new MessageContext();
        context.setMessage(artifactResponse);

        SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setRelayState("teststate");

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(SAMLRequest.URLToEndpoint("http://localhost:8080/acs"));

        // context.getSubcontext(SecurityParametersContext.class, true)
        // .setSignatureSigningParameters(new
        // SAMLRequest().buildSignatureSigningParameters());

        SAMLOutboundProtocolMessageSigningHandler handler = new SAMLOutboundProtocolMessageSigningHandler();
        handler.setSignErrorResponses(false);
        handler.initialize();

        handler.invoke(context);

        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.init();

        HTTPPostEncoder encoder = new HTTPPostEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);
        encoder.setVelocityEngine(velocityEngine);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private Response buildArtifactResponse() throws Exception {

        Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
        response.setDestination("http://localhost:8080/acs");
        response.setIssueInstant(DateTime.now());
        response.setID(OpenSAMLUtils.generateSecureRandomId());
        Issuer issuer2 = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        response.setIssuer(issuer2);

        Status status2 = OpenSAMLUtils.buildSAMLObject(Status.class);
        StatusCode statusCode2 = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion();

        signAssertion(assertion);
        EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        response.getEncryptedAssertions().add(encryptedAssertion);
        return response;
    }

    private EncryptedAssertion encryptAssertion(Assertion assertion) throws Exception {

        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(new SAMLRequest().getSenderSigningCredential());
        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

        try {
            EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
            return encryptedAssertion;
        } catch (EncryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private void signAssertion(Assertion assertion) throws Exception {
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(new IDPCredentials().generateCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private Assertion buildAssertion() {

        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(IDP_ENTITY_ID);
        assertion.setIssuer(issuer);
        assertion.setIssueInstant(DateTime.now());

        assertion.setID(OpenSAMLUtils.generateSecureRandomId());

        Subject subject = OpenSAMLUtils.buildSAMLObject(Subject.class);
        assertion.setSubject(subject);

        NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
        nameID.setFormat(NameIDType.TRANSIENT);
        nameID.setValue("Some NameID value");
        nameID.setSPNameQualifier("SP name qualifier");
        nameID.setNameQualifier("Name qualifier");

        subject.setNameID(nameID);

        subject.getSubjectConfirmations().add(buildSubjectConfirmation());

        assertion.setConditions(buildConditions());

        assertion.getAttributeStatements().add(buildAttributeStatement());

        assertion.getAuthnStatements().add(buildAuthnStatement());

        return assertion;
    }

    private SubjectConfirmation buildSubjectConfirmation() {
        SubjectConfirmation subjectConfirmation = OpenSAMLUtils.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData subjectConfirmationData = OpenSAMLUtils.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setInResponseTo("Made up ID");
        subjectConfirmationData.setNotBefore(DateTime.now());
        subjectConfirmationData.setNotOnOrAfter(DateTime.now().plusDays(7));
        subjectConfirmationData.setRecipient("http://localhost:8080/acs");

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        return subjectConfirmation;
    }

    private AuthnStatement buildAuthnStatement() {
        AuthnStatement authnStatement = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        ;
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);

        authnStatement.setAuthnInstant(DateTime.now());

        return authnStatement;
    }

    private Conditions buildConditions() {
        Conditions conditions = OpenSAMLUtils.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(DateTime.now());
        conditions.setNotOnOrAfter(DateTime.now().plusDays(7));
        AudienceRestriction audienceRestriction = OpenSAMLUtils.buildSAMLObject(AudienceRestriction.class);
        Audience audience = OpenSAMLUtils.buildSAMLObject(Audience.class);
        audience.setAudienceURI("http://localhost:8080/acs");
        ;
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AttributeStatement buildAttributeStatement() {
        AttributeStatement attributeStatement = OpenSAMLUtils.buildSAMLObject(AttributeStatement.class);

        Attribute attributeUserName = OpenSAMLUtils.buildSAMLObject(Attribute.class);

        XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(XSString.TYPE_NAME);
        XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        userNameValue.setValue("bob");

        attributeUserName.getAttributeValues().add(userNameValue);
        attributeUserName.setName("username");
        attributeStatement.getAttributes().add(attributeUserName);

        Attribute attributeLevel = OpenSAMLUtils.buildSAMLObject(Attribute.class);
        XSString levelValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        levelValue.setValue("999999999");

        attributeLevel.getAttributeValues().add(levelValue);
        attributeLevel.setName("telephone");
        attributeStatement.getAttributes().add(attributeLevel);

        return attributeStatement;

    }

    private MetadataCredentialResolver getMetadataCredentialResolver() throws Exception {
        final MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();

        // File metadataFile = new
        // File(getClass().getClassLoader().getResource(SENDER_METADATA_PATH).toURI());

        // final FilesystemMetadataResolver metadataResolver = new
        // FilesystemMetadataResolver(metadataFile);
        // metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
        // metadataResolver.setParserPool(OpenSAMLUtils.getParserPool());
        // metadataResolver.initialize();

        HTTPMetadataResolver metadataResolver = new HTTPMetadataResolver(new HttpClientBuilder().buildClient(),
                SENDER_METADATA_PATH);
        metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
        metadataResolver.setParserPool(OpenSAMLUtils.getParserPool());
        metadataResolver.initialize();

        final PredicateRoleDescriptorResolver roleResolver = new PredicateRoleDescriptorResolver(metadataResolver);

        final KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap
                .buildBasicInlineKeyInfoCredentialResolver();

        metadataCredentialResolver.setKeyInfoCredentialResolver(keyResolver);
        metadataCredentialResolver.setRoleDescriptorResolver(roleResolver);

        metadataCredentialResolver.initialize();
        roleResolver.initialize();

        return metadataCredentialResolver;
    }

    private ExplicitKeySignatureTrustEngine buildTrustEngine() throws Exception {
        final KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap
                .buildBasicInlineKeyInfoCredentialResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(
                getMetadataCredentialResolver(), keyInfoResolver);

        return trustEngine;

    }

    private SignatureValidationParameters buildSignatureValidationParameters() throws Exception {
        SignatureValidationParameters validationParameters = new SignatureValidationParameters();
        validationParameters.setSignatureTrustEngine(buildTrustEngine());
        return validationParameters;
    }

    private void verifySignatureUsingMessageHandler(MessageContext context) throws Exception {
        SecurityParametersContext secParamsContext = context.getSubcontext(SecurityParametersContext.class, true);
        secParamsContext.setSignatureValidationParameters(buildSignatureValidationParameters());

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        peerEntityContext.setEntityId(SENDER_ENTITY_ID);
        peerEntityContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        SAMLProtocolContext protocolContext = context.getSubcontext(SAMLProtocolContext.class, true);
        protocolContext.setProtocol(SAMLConstants.SAML20P_NS);

        SAMLProtocolMessageXMLSignatureSecurityHandler signatureValidationHanlder = new SAMLProtocolMessageXMLSignatureSecurityHandler();
        signatureValidationHanlder.invoke(context);

        if (!peerEntityContext.isAuthenticated()) {
            throw new SecurityException("Message not signed");
        }
    }

    @RequestMapping(value = "/IDPMetadata", method = RequestMethod.GET, produces = MediaType.APPLICATION_XML_VALUE)
    String samlMetadata(HttpServletRequest req) {

        try {

            return IDPMetadata.buildMetadata();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return e.toString();
        }
    }
}
