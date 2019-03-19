package com.rdlogic.config;

import com.rdlogic.security.DelegatingSAMLContextProviderImpl;
import com.rdlogic.security.NoTimeoutWebSSOProfileConsumerImpl;
import com.rdlogic.service.SamlUserDetailService;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.inject.Inject;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SamlWebConfig extends WebSecurityConfigurerAdapter {


    private final Log log = LogFactory.getLog(getClass());

    private Timer backgroundTaskTimer;
    private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

    @Value("${keystore.path}")
    private String keypath;
    @Value("${keystore.key}")
    private String ksKey;
    @Value("${keystore.pass}")
    private String keypass;

    @Inject
    private SamlUserDetailService userDetailService;

    @PostConstruct
    public void init() {
        this.backgroundTaskTimer = new Timer(true);
        this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
    }

    @PreDestroy
    public void destroy() {
        this.backgroundTaskTimer.purge();
        this.backgroundTaskTimer.cancel();
        this.multiThreadedHttpConnectionManager.shutdown();
    }

    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(this.multiThreadedHttpConnectionManager);
    }

    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new DelegatingSAMLContextProviderImpl();
    }

    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        NoTimeoutWebSSOProfileConsumerImpl consumer = new NoTimeoutWebSSOProfileConsumerImpl();
//        consumer.setMaxAuthenticationAge(Long.MAX_VALUE);
        return consumer;
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    @Bean
    public WebSSOProfileECPImpl expProfile() {
        return new WebSSOProfileECPImpl();
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
        profileOptions.setIncludeScoping(false);
        return profileOptions;
    }

    @Bean
    public KeyManager keyManager() {
        System.out.println("\n\n\nloading keystore - intantiating resource loader\n\n\n");
        DefaultResourceLoader loader = new DefaultResourceLoader();
        System.out.println("\n\n\nloading keystore - loading keystore at: "+keypath+"\n\n\n");
        Resource samlKeystore = loader.getResource(keypath);//"classpath:/saml/samlKeystore.jks");
        System.out.println("\n\n\nloading keystore - setting password: "+keypass+"\n\n\n");
        String storePass = keypass;//"!Qaz2wsx";
        Map<String, String> pwds = new HashMap<>();
        pwds.put(ksKey, keypass);
        System.out.println("\n\n\nloading keystore - return\n\n\n");
        return new JKSKeyManager(samlKeystore, storePass, pwds, ksKey);
    }

    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer() {
        return new TLSProtocolConfigurer();
    }

    @Bean
    public ProtocolSocketFactory socketFactory() {
        return new TLSProtocolSocketFactory(keyManager(), null, "default");
    }

    @Bean
    public Protocol socketFactoryProtocol() {
        return new Protocol("https", socketFactory(), 443);
    }

    @Bean
    public MethodInvokingFactoryBean socketFactoryInitialization() {
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setTargetClass(Protocol.class);
        methodInvokingFactoryBean.setTargetMethod("registerProtocol");
        Object[] args = {"https", socketFactoryProtocol()};
        methodInvokingFactoryBean.setArguments(args);
        return methodInvokingFactoryBean;
    }


    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    @Bean
    HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public SAMLProcessorImpl processor() {
        Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        return new SAMLProcessorImpl(bindings);
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(failureHandler());
//        samlWebSSOProcessingFilter.setSessionAuthenticationStrategy(org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy);
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
        return new FilterChainProxy(chains);
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider sap = new SAMLAuthenticationProvider();
        sap.setUserDetails(userDetailService);
        sap.setForcePrincipalAsString(false);
        return sap;
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        samlEntryPoint.setWebSSOprofile(webSSOprofile());
        return samlEntryPoint;
    }

/*    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }*/

/*
    @Bean
    public CustomRedirectConcurrentSessionFilter ccSessionFilter() {
        return new CustomRedirectConcurrentSessionFilter(sessionRegistry());
    }
*/

/*    @Bean
    public HttpSessionEventPublisher sessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }*/

/*
    @Bean
    public ClientAuthenticationSuccessHandler successHandler() {
        ClientAuthenticationSuccessHandler handler = new ClientAuthenticationSuccessHandler();
        handler.setLoginProcessingUrl("/login");
        handler.setDefaultTargetUrl("/home");
        return handler;
    }

    @Bean
    public LoginRedirectFailureHandler failureHandler() {
        return new LoginRedirectFailureHandler();
    }
*/

    // Handler deciding where to redirect user after successful login
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/landing");
        return successRedirectHandler;
    }

    // Handler deciding where to redirect user after failed login
    @Bean
    public SimpleUrlAuthenticationFailureHandler failureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler =
                new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }


/*    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler =
                new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(false);
        failureHandler.setDefaultFailureUrl("/jsp/loginerror.jsp");
        return failureHandler;
    }*/



/*    @Bean
    public SsoDelegatingAuthenticationEntryPoint entryPoint() {
        SsoDelegatingAuthenticationEntryPoint entryPoint = new SsoDelegatingAuthenticationEntryPoint();
        Set<String> ssoClients = new HashSet<>(this.ssoClients);
        entryPoint.setSsoClients(ssoClients);
        entryPoint.setLogin(new DynamicLoginUrlAuthenticationEntryPoint("login"));
        return entryPoint;
    }*/

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/**/css/**", "/**/js/**", "/gifs/**", "/images/**", "/error/**",
                "/rdm/static_01/css/**", "/rdm/static_03/css/**",
                "/rdm/static_01/js/**", "/rdm/static_03/js/**",
                "/rdm/static_01/gif/**", "/rdm/static_03/gif/**",
                "/favicon.ico");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
//        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .httpBasic()
//                .authenticationEntryPoint(samlEntryPoint());
//        http
//                .csrf()
//                .disable();
//        http
//                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
//                .addFilterBefore(clientDetailsFilter, MetadataGeneratorFilter.class)

        http
//                .requiresChannel().anyRequest().requiresSecure().channelProcessors().and()
                .authorizeRequests()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/img/**").permitAll()
                .antMatchers("/js/**").permitAll()
//                .antMatchers("/fonts/**", "**/sessionExpired.jsp", "/*/error/**",
//                "/{company:.*}", "/{company}/pwdReset", "/{company}/pwdReset/",
//                "/{company}/login", "/{company}/login/", "/{company}/support", "/{company}/support/",
//                "/js/**", "/css/**", "/gifs/**", "/**/images/**", "/rdm/static_01/**", "/rdm/static_03/**").permitAll()
                .anyRequest().authenticated()
//                .and().formLogin()
//                .loginPage("/{company:.+}/login").usernameParameter("email")
//                .successHandler(successHandler()).failureHandler(failureHandler())
                .and().csrf().disable()
//                .headers().frameOptions().disable().addHeaderWriter(new AuthenticationHeaderWriter())
//                .and()
//                .sessionManagement().maximumSessions(Integer.MAX_VALUE).sessionRegistry(sessionRegistry()).expiredUrl("/error/stub/sessionExpired").and()//.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
//                .invalidSessionStrategy(invalidSessionStrategy)//.invalidSessionUrl("/error/error")
//                .and()
                .exceptionHandling().authenticationEntryPoint(samlEntryPoint()).and()
//                .addFilterBefore(clientDetailsFilter, ChannelProcessingFilter.class)
//                .addFilterAt(ccSessionFilter(), ConcurrentSessionFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);;
//        http.addFilterBefore(clientDetailsFilter, HeaderWriterFilter.class);
    }



}
