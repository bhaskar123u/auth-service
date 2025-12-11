package com.bsharan.auth_service.loggers;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class VaultStartupLogger {

    @Bean
    CommandLineRunner logVaultSecrets(Environment env) {
        return args -> {
            System.out.println("----------------- VAULT VALUES -------------------");
            System.out.println("DB USER = "
                    + env.getProperty("spring.datasource.username"));
            System.out.println("DB URL  = "
                    + env.getProperty("spring.datasource.url"));
            System.out.println("--------------------------------------------------");
        };
    }
 
}
