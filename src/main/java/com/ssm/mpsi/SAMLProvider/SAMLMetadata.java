package com.ssm.mpsi.SAMLProvider;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.joda.time.DateTime;
import org.joda.time.Duration;
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
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class SAMLMetadata {

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
                    keyInfoGenerator.generate(new SAMLRequest().getSenderSigningCredential()));
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
                    keyInfoGenerator.generate(new SAMLRequest().getSenderSigningCredential()));
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

    private static EntityDescriptor buildEntityDescriptor() throws CertificateException, NoSuchAlgorithmException {
        EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
        entityDescriptor.setEntityID("https://imesdev.ssm4u.com.my/saml/metadata.do");
        entityDescriptor.setValidUntil(new DateTime());
        entityDescriptor.setCacheDuration(Duration.standardDays(7).getStandardDays());

        SPSSODescriptor spssoDescriptor = new SPSSODescriptorBuilder().buildObject();
        spssoDescriptor.setAuthnRequestsSigned(true);
        spssoDescriptor.setWantAssertionsSigned(false);
        spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Create and add KeyDescriptor objects
        List<KeyDescriptor> keyDescriptors = buildKeyDescriptors();
        spssoDescriptor.getKeyDescriptors().addAll(keyDescriptors);

        SingleLogoutService singleLogoutService = new SingleLogoutServiceBuilder().buildObject();
        singleLogoutService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        singleLogoutService.setLocation("https://imesdev.ssm4u.com.my/mpsi/j_spring_security_logout");
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutService);

        NameIDFormat nameIDFormat = new NameIDFormatBuilder().buildObject();
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        spssoDescriptor.getNameIDFormats().add(nameIDFormat);

        AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        assertionConsumerService.setLocation("https://imesdev.ssm4u.com.my/saml/acs");
        assertionConsumerService.setIndex(1);
        spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        entityDescriptor.getRoleDescriptors().add(spssoDescriptor);

        return entityDescriptor;
    }

    private static List<KeyDescriptor> buildKeyDescriptors() throws CertificateException, NoSuchAlgorithmException {
        ArrayList<KeyDescriptor> keyDescriptors = new ArrayList<>();

        KeyDescriptor signingKeyDescriptor = new KeyDescriptorBuilder().buildObject();
        signingKeyDescriptor.setUse(UsageType.SIGNING);
        signingKeyDescriptor.setKeyInfo(buildKeyInfo());

        KeyDescriptor encryptionKeyDescriptor = new KeyDescriptorBuilder().buildObject();
        encryptionKeyDescriptor.setUse(UsageType.ENCRYPTION);
        encryptionKeyDescriptor.setKeyInfo(buildKeyInfo());

        keyDescriptors.add(signingKeyDescriptor);
        keyDescriptors.add(encryptionKeyDescriptor);

        return keyDescriptors;
    }

    private static KeyInfo buildKeyInfo() throws CertificateException, NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Adjust the key size as needed
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Hardcoded IdP certificate
        X509Certificate idpCertificate = loadIdPCertificate();
        BasicX509Credential credential = new BasicX509Credential(idpCertificate);
        credential.setPrivateKey(keyPair.getPrivate());

        // Create the KeyInfo element
        KeyInfo keyInfo = (KeyInfo) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME)
                .buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        // Create the X509Data element
        X509Data x509Data = (X509Data) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(X509Data.DEFAULT_ELEMENT_NAME)
                .buildObject(X509Data.DEFAULT_ELEMENT_NAME);

        // Create the X509Certificate element
        org.opensaml.xmlsec.signature.X509Certificate x509Certificate = (org.opensaml.xmlsec.signature.X509Certificate) XMLObjectProviderRegistrySupport
                .getBuilderFactory()
                .getBuilder(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME)
                .buildObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);

        // Encode the IdP certificate to Base64 and set the value of X509Certificate
        // element
        x509Certificate.setValue(
                Base64.getEncoder().encodeToString(credential.getEntityCertificate().getEncoded()));

        // Add the X509Certificate element to X509Data
        x509Data.getX509Certificates().add(x509Certificate);

        // Add the X509Data to KeyInfo
        keyInfo.getX509Datas().add(x509Data);

        return keyInfo;
    }

    private static X509Certificate loadIdPCertificate() throws CertificateException {
        // Hardcode the IdP certificate
        String idpCertificateString = "MIIFNDCCBBygAwIBAgIUEroFJ+e+8UHFtKj9MSwISxKEXrowDQYJKoZIhvcNAQELBQAwMzEaMBgG"
                + "A1UECxMRT3JnYW5pemF0aW9uYWwgQ0ExFTATBgNVBAoUDERFVkFDMDFfVFJFRTAeFw0yMjA0MDMw"
                + "NzU2NTlaFw0yNDA0MDMwNzU2NTlaMEMxGDAWBgNVBAMTD3Rlc3QtZW5jcnlwdGlvbjEWMBQGA1UE"
                + "CxMNYWNjZXNzTWFuYWdlcjEPMA0GA1UEChMGbm92ZWxsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
                + "MIIBCgKCAQEAs3939g5wOdKfSRoOYvgue2TwNp7FaKB7TMxmuo3WL8t18xFrNWqyjSKmsGJhlnqH"
                + "QcWETpACMlBtR6wkrFlaj7FKEa9I89TPCkyE6MRwBHPQtEyWLMyqWBVaeQF3GcI2diSYeMBGjERt"
                + "xLtwshuuW+6hKWEGMsTypJtZxOLOWPPb6gGEghE5gXPl6l5kDqoa711JeX2HL+3PRRzWReZJ0qF0"
                + "FhOXrMjkeAmfkjNyagg5N/fUNCvAbzt/zoTt3uDmkvBzh4V5RLpOJpivA8+Oepn39Y7mL00uCziA"
                + "+y1f4JDuMC7ef5b8oUvm9eQv4ho6TBmsPcmyW7YcobU1Of69nQIDAQABo4ICLjCCAiowHQYDVR0O"
                + "BBYEFCpZa2GOYwz0tVickw8uh1eKMrtYMB8GA1UdIwQYMBaAFAVHEj1TxVtay+PRZz1X6qMKWZNs"
                + "MBgGA1UdEQQRMA+HBArcHjGCB0RFVkFDMDEwggHMBgtghkgBhvg3AQkEAQSCAbswggG3BAIBAAEB"
                + "/xMdTm92ZWxsIFNlY3VyaXR5IEF0dHJpYnV0ZSh0bSkWQ2h0dHA6Ly9kZXZlbG9wZXIubm92ZWxs"
                + "LmNvbS9yZXBvc2l0b3J5L2F0dHJpYnV0ZXMvY2VydGF0dHJzX3YxMC5odG0wggFIoBoBAQAwCDAG"
                + "AgEBAgFGMAgwBgIBAQIBCgIBaaEaAQEAMAgwBgIBAQIBADAIMAYCAQECAQACAQCiBgIBFwEB/6OC"
                + "AQSgWAIBAgICAP8CAQADDQCAAAAAAAAAAAAAAAADCQCAAAAAAAAAADAYMBACAQACCH//////////"
                + "AQEAAgQG8N9IMBgwEAIBAAIIf/////////8BAQACBAbw30ihWAIBAgICAP8CAQADDQBAAAAAAAAA"
                + "AAAAAAADCQBAAAAAAAAAADAYMBACAQACCH//////////AQEAAgQR/7CdMBgwEAIBAAIIf///////"
                + "//8BAQACBBH/sJ2iTjBMAgECAgEAAgIA/wMNAIAAAAAAAAAAAAAAAAMJAIAAAAAAAAAAMBIwEAIB"
                + "AAIIf/////////8BAQAwEjAQAgEAAgh//////////wEBADANBgkqhkiG9w0BAQsFAAOCAQEAcxj7"
                + "EcyOjaKkIe0ohUVthzQh4SC25VzUFDcV5URuq/LDsiumMRAlLHW/fA0lr5dIlJEgH2Mu6Sc9QyrU"
                + "Lg+TA4gqTqRxnvoYDRDp2xamTtFUdYzlX0mjmbbsN9zUkr83M3qXjAV0lhKCEqC9+I2s94jHMb46"
                + "8463qW26L7jr/saKmuEWoQJdYgXOeSjJQ35dn5hyLztZcF2xiOg2SVzO3NJmEUVYIJju6x4Dhx5w"
                + "MvkGa8zg87to7kXii1XYOgPhvNd5+w478nL95qcwlwYGFoze/uDcTZTBeqv6ndh4Arc+n3kaGEfl"
                + "VWAXoOOgdRvisO0fixGzXIXsf5qEG+yu2Q==";

        // Parse the certificate string
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(idpCertificateString)));
    }
}
