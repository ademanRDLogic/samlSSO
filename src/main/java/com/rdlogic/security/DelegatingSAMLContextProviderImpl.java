package com.rdlogic.security;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.trust.AllowAllSignatureTrustEngine;

public class DelegatingSAMLContextProviderImpl extends SAMLContextProviderImpl {

    public DelegatingSAMLContextProviderImpl(){
        super();
    }

    @Override
    protected void populateTrustEngine(SAMLMessageContext samlContext){
        SignatureTrustEngine engine = new AllowAllSignatureTrustEngine(Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        samlContext.setLocalTrustEngine(engine);
    }
}
