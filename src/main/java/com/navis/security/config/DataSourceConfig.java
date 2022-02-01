package com.navis.security.config;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;
import java.io.FileReader;
import java.io.IOException;

@Configuration
public class DataSourceConfig {
    @Autowired
    private ApplicationContext applicationContext;

    @Bean
    public DataSource getDataSource() {
        CSVFormat format = CSVFormat.DEFAULT.withDelimiter(',').withFirstRecordAsHeader();
        CSVParser csvParser;
        try {
            csvParser = new CSVParser(new FileReader("src/main/resources/demo.csv"), format);
        } catch (IOException e) {
            throw new RuntimeException("Cannot parse this csv file. Look into your CSV file or provide the correct location of the CSV file.", e);
        }
        String url = null;
        String envPropUsername = null;
        String envPropPassword = null;
        for (CSVRecord record : csvParser) {
            url = String.valueOf(record.get(0));
            String username = String.valueOf(record.get(1));
            String password = String.valueOf(record.get(2));
            System.out.println(url + " " + username + " " + password);
            Environment environment = applicationContext.getBean(Environment.class);
            username = username.replaceAll("\\s", "");
            username = username.substring(2, username.length() - 1);
            envPropUsername = environment.getProperty(username);

            password = password.replaceAll("\\s", "");
            password = password.substring(2, password.length() - 1);
            envPropPassword = environment.getProperty(password);
        }
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        dataSourceBuilder.url(url);
        dataSourceBuilder.username(envPropUsername);
        dataSourceBuilder.password(envPropPassword);
        System.out.println("Username/password from vault::: " + envPropUsername + "/" + envPropPassword);
        return dataSourceBuilder.build();

    }
}