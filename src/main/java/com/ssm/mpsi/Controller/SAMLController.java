package com.ssm.mpsi.Controller;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerException;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml1.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
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
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import com.ssm.mpsi.SAMLProvider.OpenSAMLUtils;
import com.ssm.mpsi.SAMLProvider.SAMLMetadata;
import com.ssm.mpsi.SAMLProvider.SAMLRequest;
import com.ssm.mpsi.SAMLProvider.SAMLResponse;
import com.ssm.mpsi.SAMLProvider.IDP.IDPCredentials;
import com.ssm.mpsi.model.Certificate;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

@RestController
public class SAMLController {

	@GetMapping("/")
	void init(HttpServletResponse resp, HttpServletRequest req) throws IOException, InterruptedException {
		resp.sendRedirect("http://localhost:8080/acs"
				+ "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");

	}

	@RequestMapping(value = "/samlReq", method = RequestMethod.GET)
	void samlReq(HttpServletResponse httpServletResponse)
			throws Exception {
		SAMLRequest samlRequest = new SAMLRequest();

		MessageContext context = new MessageContext();

		context.setMessage(samlRequest.buildAuthnRequest());
		SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
		bindingContext.setRelayState("teststate");

		SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
		endpointContext.setEndpoint(SAMLRequest.URLToEndpoint(SAMLRequest.MESSAGE_RECEIVER_ENDPOINT));

		context.getSubcontext(SecurityParametersContext.class, true)
				.setSignatureSigningParameters(samlRequest.buildSignatureSigningParameters());

		SAMLOutboundProtocolMessageSigningHandler handler = new SAMLOutboundProtocolMessageSigningHandler();
		handler.setSignErrorResponses(false);
		handler.initialize();

		handler.invoke(context);

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		encoder.setMessageContext(context);
		encoder.setHttpServletResponse(httpServletResponse);

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
		System.out.println(encoder);
	}

	private static final String SENDER_METADATA_PATH = "http://localhost:8080/IDPMetadata";
	private static final String SENDER_ENTITY_ID = "http://localhost:8080";

	@RequestMapping(value = "/acs", method = RequestMethod.POST)
	void samlRes(HttpServletRequest req, HttpServletResponse resp) throws Exception {

		// System.out.println("Artifact received");
		// Artifact artifact = buildArtifactFromRequest(req);
		// System.out.println("Artifact: " + artifact.getArtifact());

		// ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
		// System.out.println("Sending ArtifactResolve");
		// System.out.println("ArtifactResolve: ");
		// OpenSAMLUtils.logSAMLObject(artifactResolve);

		// Response artifactResponse = sendAndReceiveArtifactResolve(artifactResolve,
		// resp);
		// System.out.println("ArtifactResponse received");
		// System.out.println("ArtifactResponse: ");
		// OpenSAMLUtils.logSAMLObject(artifactResponse);

		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.setHttpServletRequest(req);

		Response artifactResponse;
		try {
			decoder.initialize();

			decoder.decode();
			MessageContext messageContext = decoder.getMessageContext();
			artifactResponse = (Response) messageContext.getMessage();
		} catch (Exception e) {
			throw new RuntimeException(e);

		}
		System.out.println("ArtifactResponse received");
		System.out.println("ArtifactResponse: ");
		OpenSAMLUtils.logSAMLObject(artifactResponse);

		validateDestinationAndLifetime(artifactResponse, req);

		EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
		Assertion assertion = decryptAssertion(encryptedAssertion);
		verifySignatureUsingSignatureValidator(assertion);
		System.out.println("Decrypted Assertion: ");
		OpenSAMLUtils.logSAMLObject(assertion);
		// verifyAssertionSignature(assertion);

		logAssertionAttributes(assertion);
		logAuthenticationInstant(assertion);
		logAuthenticationMethod(assertion);

		setAuthenticatedSession(req);
		redirectToGotoURL(req, resp);

	}

	private void validateDestinationAndLifetime(Response artifactResponse, HttpServletRequest request) {
		MessageContext context = new MessageContext();
		context.setMessage(artifactResponse);

		SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
		messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

		MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
		lifetimeSecurityHandler.setClockSkew(Duration.millis(1000).getMillis());
		lifetimeSecurityHandler.setMessageLifetime(Duration.millis(2000).getMillis());
		lifetimeSecurityHandler.setRequiredRule(true);

		ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
		receivedEndpointSecurityHandler.setHttpServletRequest(request);
		List handlers = new ArrayList<MessageHandler>();
		handlers.add(lifetimeSecurityHandler);
		handlers.add(receivedEndpointSecurityHandler);

		// BasicMessageHandlerChain handlerChain = new BasicMessageHandlerChain();
		// handlerChain.setHandlers(handlers);

		// try {
		// handlerChain.initialize();
		// handlerChain.doInvoke(context);
		// } catch (ComponentInitializationException e) {
		// throw new RuntimeException(e);
		// } catch (MessageHandlerException e) {
		// throw new RuntimeException(e);
		// }

	}

	private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) throws Exception {
		StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
				new SAMLRequest().getSenderSigningCredential());

		Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
		decrypter.setRootInNewDocument(true);

		try {
			return decrypter.decrypt(encryptedAssertion);
		} catch (DecryptionException e) {
			throw new RuntimeException(e);
		}
	}

	private void setAuthenticatedSession(HttpServletRequest req) {
		req.getSession().setAttribute("authenticated", true);
	}

	private void redirectToGotoURL(HttpServletRequest req, HttpServletResponse resp) {
		String gotoURL = (String) req.getSession().getAttribute("/");
		System.out.println("Redirecting to requested URL: " + gotoURL);
		try {
			resp.sendRedirect(gotoURL);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void logAuthenticationMethod(Assertion assertion) {
		System.out.println("Authentication method: "
				+ assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef()
						.getAuthnContextClassRef());
	}

	private void logAuthenticationInstant(Assertion assertion) {
		System.out.println("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
	}

	private void logAssertionAttributes(Assertion assertion) {
		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
			System.out.println("Attribute name: " + attribute.getName());
			for (XMLObject attributeValue : attribute.getAttributeValues()) {
				System.out.println("Attribute value: " + ((XSString) attributeValue).getValue());
			}
		}
	}

	private EncryptedAssertion getEncryptedAssertion(Response artifactResponse) {
		// Response response = (Response) artifactResponse.getMessage();
		return artifactResponse.getEncryptedAssertions().get(0);
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

	private void verifySignatureUsingSignatureValidator(Assertion assertion) throws Exception {
		// Get resolver to extract public key from metadata
		MetadataCredentialResolver metadataCredentialResolver = getMetadataCredentialResolver();

		// Set criterion to get relevant certificate
		CriteriaSet criteriaSet = new CriteriaSet();

		criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
		criteriaSet.add(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
		criteriaSet.add(new ProtocolCriterion(SAMLConstants.SAML20P_NS));
		criteriaSet.add(new EntityIdCriterion(SENDER_ENTITY_ID));

		// Resolve credential
		Credential credential = metadataCredentialResolver.resolveSingle(criteriaSet);

		// Verify signature format
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(assertion.getSignature());

		// Verify signature
		SignatureValidator.validate(assertion.getSignature(), credential);
		System.out.println("Signature verified using SignatureValidator");
	}

	@RequestMapping(value = "/samlMetadata", method = RequestMethod.GET, produces = MediaType.APPLICATION_XML_VALUE)
	String samlMetadata(HttpServletRequest req) {

		System.out.println("SCHEME : " + req.getScheme());
		System.out.println("IS SECURE : " + req.isSecure());

		try {

			return SAMLMetadata.buildMetadata();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return e.toString();
		}
	}

}
