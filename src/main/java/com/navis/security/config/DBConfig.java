package com.navis.security.config;


import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Data
@NoArgsConstructor
@Component
public class DBConfig {

    @Value("${jdbc.url:}")
    private String jdbcUrl;

    @Value("${jdbc.user:}")
    private String jdbcUser;

    @Value("${jdbc.pass:}")
    private String jdbcPassword;
}
