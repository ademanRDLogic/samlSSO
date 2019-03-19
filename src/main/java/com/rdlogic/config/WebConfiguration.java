
package com.rdlogic.config;

import org.springframework.context.annotation.*;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

@Configuration
@EnableWebMvc
@ImportResource(value = "WEB-INF/applicationContext.xml")
//@Import({SamlWebConfig.class})
@PropertySource("classpath:saml.properties")
public class WebConfiguration {

    @Bean
    public InternalResourceViewResolver viewResolver(){
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setViewClass(JstlView.class);
        viewResolver.setPrefix("/jsp/");
        viewResolver.setSuffix(".jsp");
//        viewResolver.setExposedContextBeanNames("ClientContext");
        return viewResolver;
    }

}
