package com.security.jwt.login.config;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.shaded.org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testcontainers.shaded.org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

@Configuration
@EnableConfigurationProperties
public class PropertyEncryptConfig {
    @Bean("encryptBean") //application.yml 파일 value 와 동일해야 됨.
    public PooledPBEStringEncryptor stringEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setProvider(new BouncyCastleProvider());
        encryptor.setPoolSize(2);
        encryptor.setPassword("Password");
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        return encryptor;
    }

//    public static void main(String[] args) {
//        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
//        encryptor.setProvider(new BouncyCastleProvider());
//        encryptor.setPoolSize(2);
//        encryptor.setPassword("Password");
//        encryptor.setAlgorithm("PBEWithMD5AndDES");
//
//        String username = "root";
//        String password = "root";
//        String encryptedUsername = encryptor.encrypt(username);
//        String encryptedPassword = encryptor.encrypt(password);
//        String decryptedUsername = encryptor.decrypt(encryptedUsername);
//        String decryptedPassword = encryptor.decrypt(encryptedUsername);
//        System.out.println("EncUsername:"+encryptedUsername+", DecUsername:"+decryptedUsername);
//        System.out.println("EncPassword:"+encryptedPassword+", DecPassword:"+decryptedPassword);
//
//    }
}
