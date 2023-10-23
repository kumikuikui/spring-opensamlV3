package com.ssm.mpsi.SAMLProvider.IDP;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;

import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

public class IDPCredentials {

    private static final String KEY_STORE_PASSWORD = "password";
    private static final String KEY_STORE_ENTRY_PASSWORD = "password";
    private static final String KEY_STORE_PATH = "/idpKeystore.jks";
    private static final String ENTITY_ID = "selfsigned";

    public Credential generateCredential() {
        try {
            return getSenderSigningCredential();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
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

}