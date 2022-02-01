package com.navis.security;

import com.navis.security.service.IPasswordEncypt;
import com.navis.security.service.PasswordEncyptService;
import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@EnableEncryptableProperties
@ComponentScan(basePackages = "com.navis")
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
public class DemoApplication {

    public static void main(String[] args) throws Exception {
        ApplicationContext applicationContext = SpringApplication.run(DemoApplication.class, args);
        IPasswordEncypt passwordEncypt = applicationContext.getBean(PasswordEncyptService.class);
        passwordEncypt.encryptPassword();
        passwordEncypt.encryptPasswordUsingJasypt();
        passwordEncypt.bcryptHashing();

    }
}
