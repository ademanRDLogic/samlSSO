package com.rdlogic.service;

import com.rdlogic.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import javax.inject.Named;

@Named
public class SamlUserDetailService implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        User user = new User();
        user.setUsername(credential.getNameID().getValue());
//        user.setSamlData(credential.getAuthenticationAssertion().getDOM().getTextContent());
        return user;
    }
}
