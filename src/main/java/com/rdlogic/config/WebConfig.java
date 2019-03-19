/*
package com.rdlogic.config;

import org.springframework.context.annotation.*;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

@Configuration
@ImportResource(value = "WEB-INF/applicationContext.xml")
@Import({SamlWebConfig.class})
@ComponentScan(basePackages = "com.rdlogic")
public class WebConfig extends WebMvcConfigurationSupport {

    @Bean
    public InternalResourceViewResolver viewResolver(){
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setViewClass(JstlView.class);
        viewResolver.setPrefix("/jsp/");
        viewResolver.setSuffix(".jsp");
        viewResolver.setExposedContextBeanNames("ClientContext");
        return viewResolver;
    }

    @Override
    @Bean
    public RequestMappingHandlerMapping requestMappingHandlerMapping() {
        RequestMappingHandlerMapping handlerMapping = super.requestMappingHandlerMapping();
        handlerMapping.setOrder(1);
        return handlerMapping;
    }
}
*/