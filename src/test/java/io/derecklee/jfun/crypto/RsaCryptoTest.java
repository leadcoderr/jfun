package io.derecklee.jfun.crypto;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@Slf4j
public class RsaCryptoTest {



  @Test
  public void testReadAndInit() {
    try {
      String publicKeyPem = readPemFile("/public_key.pem");
      String privateKeyPem = readPemFile("/private_key.pem");

      // Truncate the starting line and the ending line
      byte[] publicKeyBytes = Base64
              .getDecoder()
              .decode(publicKeyPem.replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", ""));

      byte[] privateKeyBytes = Base64
              .getDecoder()
              .decode(privateKeyPem.replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", ""));

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

      byte[] privateKeyBytes = privateKey.getEncoded();
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
    } catch (NoSuchAlgorithmException e) {
      log.error(">> Invalid algorithm name ", e);
    } catch (IOException e) {
      log.error("", e);
    }
  }

  /** Optional key size: 1024,2048 */
  @Test
  public void genKeys() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048, new SecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();

      log.info("PublicKey ->{}", publicKey);
      log.info("PrivateKey->{}", privateKey);
    } catch (NoSuchAlgorithmException e) {
      log.error("RSA error", e);
    }
  }

  @Test
  public void testInitKeysFromPEMFiles() {

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

  @Test
  public void test() {
    try {
      // Read PEM files and create key objects (see previous code)


    } catch (Exception e) {
      e.printStackTrace();
    }
  }





}
