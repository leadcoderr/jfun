package io.derecklee.jfun.crypto;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

/**
 * If You want to test RSA, you must generate keys correctly, using openssl commands and make sure
 * that you have format private key as PKCS#8
 *
 * @author dereckleemj@gmail.com
 */
@Slf4j
public class RsaCryptoTest {

  @Test
  public void testReadAndInit() {
    try {
      String publicKeyPem = readPemFile("/public_key.pem");
      String privateKeyPem = readPemFile("/private_key.pem");

      // Truncate the starting line and the ending line
      String truncatedPubKey =
          publicKeyPem.replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "");
      truncatedPubKey = truncatedPubKey.replaceAll("\n", "");
      truncatedPubKey = truncatedPubKey.replaceAll("\r", "");
      System.out.println("truncatedPubKey = " + truncatedPubKey);
      byte[] publicKeyBytes = Base64.getDecoder().decode(truncatedPubKey);

      String truncatedPriKey =
          privateKeyPem.replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "");
      truncatedPriKey = truncatedPriKey.replaceAll("\n", "");
      truncatedPriKey = truncatedPriKey.replaceAll("\r", "");
      System.out.println("truncatedPriKey = " + truncatedPriKey);
      byte[] privateKeyBytes = Base64.getDecoder().decode(truncatedPriKey);

      // Get pub key: ASN.1 encoding of a public key
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

      // Get the pri key: ASN.1 encoding of a private key
      PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
      keyFactory = KeyFactory.getInstance("RSA");
      PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);

      log.info("RSA keys initialized successfully.");
    } catch (Exception e) {
      log.error("", e);
    }
  }

  private byte[] loadPemFileContent(String resource) throws IOException {
    URL url = getClass().getResource(resource);
    InputStream in = url.openStream();
    String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
    String encoded = parse.matcher(pem).replaceFirst("$1");
    log.debug(">> Loaded file: " + encoded);
    return Base64.getMimeDecoder().decode(encoded);
  }

  @Test
  public void testLoadRsaPemFiles() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    // ------------------ How to gen RSA KEYS -------------------------
    // openssl genrsa -out private.pem 1024
    // openssl pkcs8 -topk8 -inform PEM -in private.pem -out private_key.pem -nocrypt
    PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(loadPemFileContent("/private_key.pem")));

    // openssl rsa -in private.pem -pubout -outform PEM -out public_key.pem
    PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(loadPemFileContent("/public_key.pem")));

    // Certificate crt = cf.generateCertificate(getClass().getResourceAsStream("test.crt"));
  }

  /**
   * Read pem and get it text content
   *
   * @param filename class path file path
   * @return Base64 encoded key content
   */
  public String readPemFile(String filename) throws IOException {
    if (filename == null) {
      throw new IllegalArgumentException("filename can not be null");
    }

    StringBuilder strBuilder = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(getClass().getResourceAsStream(filename)))) {

      String line = null;
      while ((line = reader.readLine()) != null) {
        strBuilder.append(line).append("\n");
      }
    }

    return strBuilder.toString();
  }

  /** 将生成的RSA密钥对保存到.pem文件 */
  @Test
  public void genAndSaveAsPemFiles() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

      keyPairGenerator.initialize(2048, new SecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();

      // Convert keys to PEM format
      byte[] publicKeyBytes = publicKey.getEncoded();
      String publicKeyPem = Base64.getEncoder().encodeToString(publicKeyBytes);

      PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      byte[] privateKeyBytes = privateKeySpec.getEncoded();
      String privateKeyPem = Base64.getEncoder().encodeToString(privateKeyBytes);

      // Save keys to PEM files
      try (FileWriter writer = new FileWriter("public_key.pem")) {
        writer.write("-----BEGIN PUBLIC KEY-----\n");
        writer.write(publicKeyPem);
        writer.write("\n-----END PUBLIC KEY-----\n");
      }

      try (FileWriter writer = new FileWriter("private_key.pem")) {
        writer.write("-----BEGIN PRIVATE KEY-----\n");
        writer.write(privateKeyPem);
        writer.write("\n-----END PRIVATE KEY-----\n");
      }

      log.info("RSA key pair generated and saved as PEM files.");
    } catch (NoSuchAlgorithmException | IOException e) {
      log.error("", e);
    }
  }

  /** Optional key size: 1024,2048,4096 */
  @Test
  public void genKeys() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048, new SecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();

      // Way more things to be done

      log.info("PublicKey ->{}", publicKey);
      log.info("PrivateKey->{}", privateKey);
    } catch (NoSuchAlgorithmException e) {
      log.error("RSA error", e);
    }
  }

  @Test
  public void testEncryption() {
    try {
      KeyPairGenerator keysGenerator = KeyPairGenerator.getInstance("RSA");

      keysGenerator.initialize(2048, new SecureRandom());
      KeyPair keys = keysGenerator.generateKeyPair();

      PublicKey pubKey = keys.getPublic();
      PrivateKey priKey = keys.getPrivate();

      // Encrypt text
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, pubKey);

      byte[] plainBytes = "Hello, world!".getBytes();
      byte[] cipherBytes = cipher.doFinal(plainBytes); // Encrypt it
      String cipherText = Base64.getEncoder().encodeToString(cipherBytes);

      // Decrypt text: init the de-cipher
      cipher.init(Cipher.DECRYPT_MODE, priKey);
      byte[] decryptedTextBytes =
          cipher.doFinal(Base64.getDecoder().decode(cipherText)); // Decrypt it
      String plainText = new String(decryptedTextBytes);

      log.info("Ciphertext: {}", cipherText);
      log.info("Plaintext : {}", plainText);

    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | IllegalBlockSizeException
        | BadPaddingException
        | InvalidKeyException e) {
      // So much fucking annoying exceptions ....
      log.error("RSA error ", e);
    }
  }
}
