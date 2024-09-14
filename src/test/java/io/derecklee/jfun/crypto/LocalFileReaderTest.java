package io.derecklee.jfun.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

/** Just some file reading test */
@Slf4j
public class LocalFileReaderTest {

  @Test
  public void testRead() {
    Path filePath = Paths.get("S:/CodeWorks/github/jfun/src/main/resources/private_key.pem");

    // We have open input stream
    // We can
    try (InputStream inputStream = Files.newInputStream(filePath)) {
      int bytesRead;
      byte[] buffer = new byte[1024];

      // the total number of bytes read into the buffer
      while ((bytesRead = inputStream.read(buffer)) != -1) {
        // Write out 0 ~ bytesRead
        System.out.write(buffer, 0, bytesRead);
      }

    } catch (IOException e) {
      log.info("Error happen while reading local file ", e);
    }
  }
}
