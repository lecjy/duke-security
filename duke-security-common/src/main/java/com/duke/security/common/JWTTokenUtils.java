package com.duke.security.common;

import com.duke.common.base.utils.JacksonUtils;
import com.duke.security.common.sys.user.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Component
public class JWTTokenUtils {

    @Value("${duke-server.private-key}")
    public void setPrivateKey(String privateKey) {
        JWTTokenUtils.privateKey = privateKey;
    }

    @Value("${duke-server.public-key}")
    public void setPublicKey(String publicKey) {
        JWTTokenUtils.publicKey = publicKey;
    }

    private static String publicKey;
    private static String privateKey;

    public static String generateToken(User user) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return generateToken(user, 1800, ChronoUnit.MINUTES);
    }

    private static String generateToken(User user, int expire, ChronoUnit unit) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 计算超时时间，带时区的时间
        ZonedDateTime zdt = LocalDateTime.now().plus(expire, unit).atZone(ZoneId.systemDefault());
        Date expireDate = Date.from(zdt.toInstant());
        return Jwts.builder()
                .claim(JWT_USER_INFO_KEY, JacksonUtils.toJSONString(User.builder()
                        .id(user.getId())
                        .name(user.getName())
                        .account(user.getAccount())
                        .tenantId(user.getTenantId())
                        .departId(user.getDepartId())
                        .roleId(user.getRoleId())
                        .build()))
                .setId(UUID.randomUUID().toString())
                .setExpiration(expireDate)
                .signWith(getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public static User userInfo(String token) {
        Jws<Claims> claimsJws = parseToken(token);
        Claims body = claimsJws.getBody();
        return JacksonUtils.parseObject(body.get(JWT_USER_INFO_KEY).toString(), User.class);
    }

    private static Jws<Claims> parseToken(String token) {
        try {
            JwtParser parser = Jwts.parserBuilder().setSigningKey(getPublicKey()).build();
            return parser.parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token已过期：" + e.getMessage());
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token不被支持：" + e.getMessage());
        } catch (MalformedJwtException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token格式不正确：" + e.getMessage());
        } catch (SignatureException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token签名错误：" + e.getMessage());
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token参数不正确：" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new AccessDeniedException("Token不正确");
        }
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    private static PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    public static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    public static final String JWT_USER_INFO_KEY = "duke-server-login-user";

    public static void main(String[] args) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
////        kpg.initialize(2048, new SecureRandom());
//        kpg.initialize(2048);
//        KeyPair kp = kpg.generateKeyPair();
//        PrivateKey privateKey = kp.getPrivate();
//        PublicKey publicKey = kp.getPublic();
//        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
//        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
//        System.out.println(publicKeyString);
//        System.out.println(privateKeyString);
////        OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream("PubKey.key"));
////        osw.write(publicKeyString);
////        osw.flush();
////        osw.close();
////        OutputStreamWriter osw2 = new OutputStreamWriter(new FileOutputStream("PriKey.key"));
////        osw2.write(privateKeyString);
////        osw2.flush();
////        osw2.close();
    }
}
