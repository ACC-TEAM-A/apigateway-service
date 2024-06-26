package com.eureka.gatewayservice.filter;

import com.eureka.gatewayservice.security.JwtProvider;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.sql.SQLOutput;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
//    @Value("${}")
//    private String secret;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // Put configuration properties here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();


            HttpHeaders headers = request.getHeaders();

            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                ServerHttpRequest newRequest = request.mutate()
                        .header("id", "guest")
                        .build();
                return chain.filter(exchange.mutate().request(newRequest).build());

            }

//            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
//            }



            Set<String> keys = headers.keySet();
            log.info(">>>");
            keys.forEach(v -> {
                log.info(v + "=" + request.getHeaders().get(v));
            });
            log.info("<<<");

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);




            if (!JwtProvider.validateToken(authorizationHeader)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);

        byte[] bytes = "The requested token is invalid.".getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return response.writeWith(Flux.just(buffer));
    }

//    public boolean validateToken(String token) {
//        try {
//            // Bearer 검증
//            if (!token.substring(0, "BEARER ".length()).equalsIgnoreCase("BEARER ")) {
//
//                System.out.println("if" + token);
//
//                return false;
//            }
//            token = token.substring("BEARER ".length()).trim();
//
//            System.out.println("else " + token);
//
//            Claims claims = Jwts.parserBuilder()
//                    .setSigningKey(secret)
//                    .build()
//                    .parseClaimsJws(token)
//                    .getBody();
//            // 토큰의 만료 시간을 확인하여 유효한지 검증
//            Date expiration = claims.getExpiration();
//            Date now = new Date();
//            if (expiration != null && expiration.before(now)) {
//                return false;
//            }
//            return true;
//        } catch (Exception e) {
//            e.printStackTrace();
//            return false;
//        }
//    }




}
