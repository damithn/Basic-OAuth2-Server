package com.damithtech.oauthserver.conf;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author DAMITH SAMARAKOON on 5/22/2020
 */
@Configuration
public class UserConfiguration extends GlobalAuthenticationConfigurerAdapter {

    PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("damith").password(passwordEncoder.encode("damith123")).roles("USER",
                                                                                                             "ADMIN",
                                                                                                             "MANAGER").authorities(
                "CAN_READ", "CAN_WRITE", "CAN_DELETE").and().withUser("testuser").password(
                passwordEncoder.encode("user123")).roles("USER").authorities(
                "CAN_READ", "CAN_WRITE");
    }
}
