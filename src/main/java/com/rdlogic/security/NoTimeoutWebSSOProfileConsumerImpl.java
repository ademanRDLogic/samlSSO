package com.rdlogic.security;

import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;

public class NoTimeoutWebSSOProfileConsumerImpl extends WebSSOProfileConsumerImpl {

    protected void verifyAuthenticationStatement(AuthnStatement auth, RequestedAuthnContext requestedAuthnContext, SAMLMessageContext context) throws AuthenticationException {
        verifyAuthnContext(requestedAuthnContext, auth.getAuthnContext(), context);
    }
}
