package com.rdlogic.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.function.Supplier;

@Configuration
public class MetadataConfig {

    @Value("${test.idp}")
    private String testIdp;
    @Value("${test.sp}")
    private String testSp;

    @Value("${keystore.key}")
    private String ksKey;

    private Timer backgroundTaskTimer;
    private final Log log = LogFactory.getLog(getClass());

    @Inject
    private StaticBasicParserPool parserPool;

    @PostConstruct
    public void init() {
        backgroundTaskTimer = new Timer(true);
    }

    private ExtendedMetadata buildIDPExtendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setEcpEnabled(true);
        return extendedMetadata;
    }
    private ExtendedMetadata buildLocalExtendedMetadata(String alias) {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(true);
        extendedMetadata.setSignMetadata(true);
        extendedMetadata.setSecurityProfile("metaiop");
        extendedMetadata.setSslSecurityProfile("pkix");
        extendedMetadata.setEncryptionKey(ksKey);
        extendedMetadata.setSigningKey(ksKey);
        extendedMetadata.setRequireArtifactResolveSigned(false);
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setEcpEnabled(true);
        extendedMetadata.setAlias(alias);
        return extendedMetadata;
    }
    private ExtendedMetadataDelegate delegateFromExtendedMetadata(String res, Supplier<ExtendedMetadata> extendedMetadataSupplierMetadata) throws MetadataProviderException, ResourceException {
        ResourceBackedMetadataProvider metadataProvider = new ResourceBackedMetadataProvider(backgroundTaskTimer,
                new ClasspathResource(res));
        metadataProvider.setParserPool(parserPool);
        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadataSupplierMetadata.get());
        delegate.setMetadataTrustCheck(false);
        delegate.initialize();
        return delegate;
    }


    @Bean
    public ExtendedMetadata testSPMetadata() {
        return buildLocalExtendedMetadata("test");
    }
    @Bean
    ExtendedMetadataDelegate testSPMetadataDelegate() throws ResourceException, MetadataProviderException {
        return delegateFromExtendedMetadata(testSp,this::testSPMetadata);
    }

    @Bean
    public ExtendedMetadata testIDPMetadata() {
        return buildIDPExtendedMetadata();
    }
    @Bean
    ExtendedMetadataDelegate testIDPMetadataDelegate() throws ResourceException, MetadataProviderException {
        return delegateFromExtendedMetadata(testIdp,this::testIDPMetadata);
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException, IOException {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(testIDPMetadataDelegate());
        providers.add(testSPMetadataDelegate());
        CachingMetadataManager cmm = new CachingMetadataManager(providers);
        return cmm;
    }


}
