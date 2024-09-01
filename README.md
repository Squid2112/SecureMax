# SecureMax - Java Security Library

**SecureMax** is a robust Java security library designed to enhance the security of applications through advanced encryption, encoding, and data manipulation techniques. With a focus on reliability and efficiency, SecureMax offers a suite of tools for developers needing secure data processing, particularly in environments like ColdFusion.

## Features

- **Advanced Encryption**: Secure your data with multiple encryption algorithms, including TripleDES.
- **Data Encoding**: Encode and decode data using Base64, Hexadecimal, and custom methods like HexTrig.
- **Data Threading**: Unique data processing technique using the `smThreader` class for secure data manipulation.
- **Error Handling**: Comprehensive error management with `smErrors` and `smErrorElement` classes.
- **CRC and Adler Checksums**: Built-in CRC32 and Adler32 checksum utilities for data integrity verification.

## Installation

To include SecureMax in your project, simply clone this repository:

```bash
git clone https://github.com/Squid2112/SecureMax.git
```

## Usage
### Encryption Example
```java
import com.thixo.security.securemax.smDESencrypt;

public class Example {
    public static void main(String[] args) {
        String passphrase = "your_passphrase";
        String data = "Sensitive Data";

        String encrypted = smDESencrypt.TripleDESencrypt(passphrase, data);
        String decrypted = smDESencrypt.TripleDESdecrypt(passphrase, encrypted);

        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
```

### Data Threading Example
```java
import com.thixo.security.securemax.smThreader;

public class Example {
    public static void main(String[] args) {
        smThreader threader = new smThreader();
        
        String key = "KeyData";
        String value = "ValueData";

        String threaded = threader.smEnthread(key, value);
        String[] dethreaded = threader.smDethread(threaded);

        System.out.println("Threaded: " + threaded);
        System.out.println("Key: " + dethreaded[0]);
        System.out.println("Value: " + dethreaded[1]);
    }
}
```

## Key Classes

- **smThreader: Encodes and decodes (threads and dethreads) data for secure storage and transfer. Uses a unique bitwise operation approach to mix and secure data.
- **smDESencrypt: Provides encryption and decryption using the TripleDES algorithm, offering a secure way to handle sensitive information.
- **smBase64: A utility class for encoding and decoding data to and from Base64.
- **smHexTrig: Converts data into a HexTrig (Base36) string format, a compact representation often used for checksums.
- **smCRC32: Generates CRC32 checksums for data integrity verification.
- **smAdler32: Similar to CRC32, but uses the Adler-32 checksum algorithm for faster computation.
- **smErrors and smErrorElement: Manages and records errors, providing detailed information for debugging and error handling.

## Running Tests

SecureMax includes a comprehensive suite of unit tests to ensure the reliability of its functionality. You can run the tests using Maven:
```bash
mvn test
```

## Contributing

Contributions are welcome! Please fork this repository, create a feature branch, and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
