package io.derecklee.jfun.crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Pem file content holder
 *
 * @author dereckleemj@gmail.com
 */
public class PemFile {

  private final PemObject pemObject;

  public PemFile(Key key, String description) {
    this.pemObject = new PemObject(description, key.getEncoded());
  }

  public void write(String filename) throws IOException {
    OutputStream fileOut = Files.newOutputStream(Paths.get(filename));
    try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(fileOut))) {
      pemWriter.writeObject(this.pemObject);
    }
  }
}
