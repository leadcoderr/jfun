package io.derecklee.jfun.crypto;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

/**
 * Q: I have already gen 2 RSA pem key files, But I fail to init keys by reading them. I want to
 * know why
 *
 * @author dereckleemj@gmail.com
 */
public class RsaKeyTest {

  private static String getKey(String filename) throws IOException {
    // Read key from file
    String strKeyPEM = "";
    BufferedReader br = new BufferedReader(new FileReader(filename));
    String line;
    while ((line = br.readLine()) != null) {
      strKeyPEM += line + "\n";
    }
    br.close();
    return strKeyPEM;
  }

  public static RSAPrivateKey getPrivateKey(String filename)
      throws IOException, GeneralSecurityException {
    String privateKeyPEM = getKey(filename);
    return getPrivateKeyFromString(privateKeyPEM);
  }

  public static RSAPrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {

    String privateKeyPEM = key;
    privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
    privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");

    byte[] encoded = Base64.decodeBase64(privateKeyPEM);

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);

    return privKey;
  }

  public static RSAPublicKey getPublicKey(String filename)
      throws IOException, GeneralSecurityException {
    String publicKeyPEM = getKey(filename);
    return getPublicKeyFromString(publicKeyPEM);
  }

  /** Read the key content and init pub key */
  public static RSAPublicKey getPublicKeyFromString(String key) throws GeneralSecurityException {
    String publicKeyPEM = key;

    publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
    publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

    byte[] encoded = Base64.decodeBase64(publicKeyPEM);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    // What ????
    // RSA pub key use X509 scheme to encode the key
    RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));

    return pubKey;
  }

  /** 使用RSA + SHA1来进行数字签名 */
  public static String sign(PrivateKey privateKey, String message)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

    Signature sign = Signature.getInstance("SHA1withRSA");
    sign.initSign(privateKey);
    sign.update(message.getBytes(StandardCharsets.UTF_8));

    return new String(Base64.encodeBase64(sign.sign()), StandardCharsets.UTF_8);
  }

  /** 使用RSA + SHA1来进行验证(验证是使用公钥) */
  public static boolean verify(PublicKey publicKey, String message, String signature)
      throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

    Signature sign = Signature.getInstance("SHA1withRSA");
    sign.initVerify(publicKey);
    sign.update(message.getBytes(StandardCharsets.UTF_8));

    return sign.verify(Base64.decodeBase64(signature.getBytes(StandardCharsets.UTF_8)));
  }

  /** RSA加密文本 */
  public static String encrypt(String rawText, PublicKey publicKey)
      throws IOException, GeneralSecurityException {

    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(StandardCharsets.UTF_8)));
  }

  /** RSA解密文本 */
  public static String decrypt(String cipherText, PrivateKey privateKey)
      throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), StandardCharsets.UTF_8);
  }

  // -------------------- Here comes the unit test --------------------




}
