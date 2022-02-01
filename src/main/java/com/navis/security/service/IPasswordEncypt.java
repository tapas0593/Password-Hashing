package com.navis.security.service;

import com.navis.security.model.TestObject;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface IPasswordEncypt {

    void encryptPassword() throws GeneralSecurityException, IOException;

    void encryptPasswordUsingJasypt();

    void bcryptHashing();

    TestObject getTestObjectUsingRest();

    void getPasswordsFromCSV() throws IOException;
}
