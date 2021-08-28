package com.okoroefe.demo.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestHeader;

import javax.crypto.SecretKey;

@ConfigurationProperties(prefix = "application.jwt")
@Configuration
public class JwtConfig {
    private String secret;
    private String tokenPrefix;
    private int tokenExpirationInDays;

    public JwtConfig() {
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public int getTokenExpirationInDays() {
        return tokenExpirationInDays;
    }

    public void setTokenExpirationInDays(int tokenExpirationInDays) {
        this.tokenExpirationInDays = tokenExpirationInDays;
    }



    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
