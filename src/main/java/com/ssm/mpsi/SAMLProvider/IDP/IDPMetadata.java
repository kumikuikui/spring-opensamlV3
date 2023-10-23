package com.ssm.mpsi.SAMLProvider.IDP;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.w3c.dom.Element;

import com.ssm.mpsi.SAMLProvider.OpenSAMLUtils;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class IDPMetadata {

    public static String buildMetadata() throws MarshallingException, CertificateException, NoSuchAlgorithmException {
        // Build SP metadata
        EntityDescriptor spEntityDescriptor = OpenSAMLUtils.buildSAMLObject(EntityDescriptor.class);
        spEntityDescriptor.setEntityID("http://localhost:8080");
        SPSSODescriptor spSSODescriptor = OpenSAMLUtils.buildSAMLObject(SPSSODescriptor.class);

        spSSODescriptor.setWantAssertionsSigned(true);
        spSSODescriptor.setAuthnRequestsSigned(true);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyDescriptor encKeyDescriptor = OpenSAMLUtils.buildSAMLObject(KeyDescriptor.class);

        encKeyDescriptor.setUse(UsageType.ENCRYPTION); // Set usage

        // Generating key info. The element will contain the public key. The key is used
        // to by the IDP to encrypt data
        try {
            encKeyDescriptor.setKeyInfo(
                    keyInfoGenerator.generate(new IDPCredentials().generateCredential()));
        } catch (SecurityException e) {
            System.out.println(e);
            ;
        } catch (org.opensaml.security.SecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);

        KeyDescriptor signKeyDescriptor = OpenSAMLUtils.buildSAMLObject(KeyDescriptor.class);

        signKeyDescriptor.setUse(UsageType.SIGNING); // Set usage

        // Generating key info. The element will contain the public key. The key is used
        // to by the IDP to verify signatures
        try {
            signKeyDescriptor.setKeyInfo(
                    keyInfoGenerator.generate(new IDPCredentials().generateCredential()));
        } catch (SecurityException e) {
            System.out.println(e);
            ;
        } catch (org.opensaml.security.SecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);

        // Request transient pseudonym
        NameIDFormat nameIDFormat = OpenSAMLUtils.buildSAMLObject(NameIDFormat.class);
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        spSSODescriptor.getNameIDFormats().add(nameIDFormat);

        SingleLogoutService singleLogoutService = OpenSAMLUtils.buildSAMLObject(SingleLogoutService.class);
        singleLogoutService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        singleLogoutService.setLocation("logoutUrl");
        spSSODescriptor.getSingleLogoutServices().add(singleLogoutService);

        AssertionConsumerService assertionConsumerService = OpenSAMLUtils
                .buildSAMLObject(AssertionConsumerService.class);
        assertionConsumerService.setIndex(0);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        // Setting address for our AssertionConsumerService
        assertionConsumerService.setLocation("acsUrl");
        spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);

        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(spEntityDescriptor);
        Element metadataElement = marshaller.marshall(spEntityDescriptor);
        return SerializeSupport.nodeToString(metadataElement);
    }

}
