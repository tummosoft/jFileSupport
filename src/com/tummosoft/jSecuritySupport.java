package com.tummosoft;

import java.awt.MouseInfo;
import java.awt.Point;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import anywheresoftware.b4a.BA;
import anywheresoftware.b4a.BA.ShortName;

@ShortName("jSecuritySupport")
public class jSecuritySupport {
    public static float jreVersion() {
        return Float.parseFloat(System.getProperty("java.version").substring(0, 3));
    }

    private static String os() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("windows")) {
            return "win";

        } else if (os.contains("linux")) {
            return "linux";

        } else if (os.contains("mac")) {
            return "mac";

        } else {
            return "other";
        }
    }

    public static boolean isLinux() {
        return os().contains("linux");
    }

    public static boolean isMac() {
        return os().contains("mac");
    }

    public static boolean isWindows() {
        return os().contains("win");
    }
    
    public static long getAvaliableMemory() {
        Runtime r = Runtime.getRuntime();
        return r.maxMemory() - (r.totalMemory() - r.freeMemory());
    }

    public static long getAvaliableMemoryMB() {
        return getAvaliableMemory() / (1024 * 1024L);
    }
    
    public static void SignatureAlgorithms() {
        try {
            for (Provider provider : Security.getProviders()) {
                for (Provider.Service service : provider.getServices()) {
                    if (service.getType().equals("Signature")) {
                        BA.Log(service.getAlgorithm());
                    }
                }
            }
        } catch (Exception e) {
            BA.Log(e.toString());
        }
    }

    public static byte[] MD5_Bytes(byte[] bytes) {
        return messageDigest(bytes, "MD5");
    }

    public static byte[] SHA1_Bytes(byte[] bytes) {
        return messageDigest(bytes, "SHA-1");
    }

    public static byte[] SHA256_Bytes(byte[] bytes) {
        return messageDigest(bytes, "SHA-256");
    }

    public static byte[] MD5_File(File file) {
        return messageDigest2(file, "MD5");
    }

    public static byte[] SHA1_File(File file) {
        return messageDigest2(file, "SHA-1");
    }

    public static byte[] SHA256_File(File file) {
        return messageDigest2(file, "SHA-256");
    }

    public static byte[] messageDigest(byte[] bytes, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(bytes);
            return digest;
        } catch (Exception e) {
            BA.Log(e.toString());
            return null;
        }
    }

    public static byte[] messageDigest2(File file, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
                byte[] buf = new byte[8024];
                int len;
                while ((len = in.read(buf)) != -1) {
                    md.update(buf, 0, len);
                }
            }
            byte[] digest = md.digest();
            return digest;
        } catch (Exception e) {
            BA.Log(e.toString());
            return null;
        }

    }
    
}
