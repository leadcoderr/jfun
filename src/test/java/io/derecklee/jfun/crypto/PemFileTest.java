package io.derecklee.jfun.crypto;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

@Slf4j
public class PemFileTest {

  public static final int KEY_SIZE = 2048;

  @Test
  public void testGenPemFile() {
    Security.addProvider(new BouncyCastleProvider());
    log.info(">> BouncyCastle provider added.");

    try {
      KeyPair keyPair = generateRSAKeyPair();

      RSAPrivateKey priKey = (RSAPrivateKey) keyPair.getPrivate();
      RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

      writePemFile(priKey, "RSA PRIVATE KEY", "id_rsa");
      writePemFile(pubKey, "RSA PUBLIC KEY", "id_rsa.pub");

    } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
      log.error("", e);
    }
  }

  private static KeyPair generateRSAKeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(KEY_SIZE);

    KeyPair keyPair = generator.generateKeyPair();
    log.info("RSA key pair generated.");

    return keyPair;
  }

  private static void writePemFile(Key key, String description, String filename)
      throws IOException {

    PemFile pemFile = new PemFile(key, description);
    pemFile.write(filename);

    log.info("{} successfully written in file {}.", description, filename);
  }
}
