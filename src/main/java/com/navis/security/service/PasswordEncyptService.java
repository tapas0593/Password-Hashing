package com.navis.security.service;

import com.navis.security.model.TestObject;
import com.navis.security.repository.TestObjectRepository;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Service
public class PasswordEncyptService implements IPasswordEncypt {

    @Value("{secret.password}")
    private String secretPassword;

    @Value("${raw.password}")
    private String password;

    @Value("${encrypt.password}")
    private String encryptPassword;

//    @Value("${db.username}")
//    private String dbUsername;

    @Autowired
    private TestObjectRepository testObjectRepository;

    private SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec); 
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }

    private String encrypt(String property, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters parameters = pbeCipher.getParameters();
        IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
        byte[] cryptoText = pbeCipher.doFinal(property.getBytes("UTF-8"));
        byte[] iv = ivParameterSpec.getIV();
        return base64Encode(iv) + ":" + base64Encode(cryptoText);
    }

    private String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String decrypt(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
        String iv = string.split(":")[0];
        String property = string.split(":")[1];
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
        return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
    }

    private byte[] base64Decode(String property) throws IOException {
        return Base64.getDecoder().decode(property);
    }

    @Override
    public void encryptPassword() throws GeneralSecurityException, IOException {

        if (secretPassword == null) {
            throw new IllegalArgumentException("Run with -Dpassword=<password>");
        }

        // The salt (probably) can be stored along with the encrypted data
        byte[] salt = new String("12345678").getBytes();

        // Decreasing this speeds down startup time and can be useful during testing, but it also makes it easier for brute force attackers
        int iterationCount = 40000;
        // Other values give me java.security.InvalidKeyException: Illegal key size or default parameters
        int keyLength = 128;
        SecretKeySpec key = createSecretKey(secretPassword.toCharArray(),
                salt, iterationCount, keyLength);

        String originalPassword = password;
        System.out.println("Original password: " + originalPassword);
        String encryptedPassword = encrypt(originalPassword, key);
        System.out.println("Encrypted password: " + encryptedPassword);
        String decryptedPassword = decrypt(encryptedPassword, key);
        System.out.println("Decrypted password: " + decryptedPassword);
    }

    @Override
    public void encryptPasswordUsingJasypt() {
        System.out.println("=========== Jasypt Encyption Method ==============");
        System.out.println("Original password::: " + password);
        TestObject testObject = new TestObject();
//        testObject.setId(1L);
        testObject.setName("Tapas(Boot run)");
        TestObject testObject1 = testObjectRepository.save(testObject);
        System.out.println("Object::: " + testObject1.getName());

        System.out.println("============== BasicTextEncryptor ================");
        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        String privateData = password;
        textEncryptor.setPasswordCharArray("postgres111".toCharArray());
        String myEncryptedText = textEncryptor.encrypt(privateData);
        System.out.println("Original password:: " + password);

        System.out.println("Encrypted password:: " + myEncryptedText);
        String plainText = textEncryptor.decrypt(myEncryptedText);
        System.out.println("Decrypted password:: " + plainText);

        System.out.println("======= One-Way Encyption ============");
        BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        System.out.println("Encrypted password:: " + encryptedPassword);
        boolean result = passwordEncryptor.checkPassword(password, encryptedPassword);
        System.out.println("Does it match...??  " + result);
    }

    @Override
    public void bcryptHashing() {
        String originalPassword = password;
        String generatedSecuredPasswordHash = BCrypt.hashpw(originalPassword, BCrypt.gensalt(12));
        System.out.println("Encrypted password::: " + generatedSecuredPasswordHash);
        boolean matched = BCrypt.checkpw(originalPassword, generatedSecuredPasswordHash);
        System.out.println(matched);
//        System.out.println(dbUsername);
        getPasswordsFromCSV();
    }

    @Override
    public TestObject getTestObjectUsingRest() {
        TestObject testObject = new TestObject();
//        testObject.setId(2L);
        testObject.setName("TestObject(Rest API)" + Math.random());
        TestObject testObject1 = testObjectRepository.save(testObject);
        System.out.println("Object::: " + testObject1.getName());
        getPasswordsFromCSV();
        return testObject1;
    }

    @Override
    public void getPasswordsFromCSV() {
        TestObject testObject = new TestObject();
        testObject.setName("TestObject(CSV File)");
        TestObject testObject1 = testObjectRepository.save(testObject);
        System.out.println("Object saved using the datasource from csv file::: " + testObject1.getName());
    }
}