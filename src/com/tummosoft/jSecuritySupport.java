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
    
    public static void listAllThreads() {
        ThreadGroup currentThreadGroup = Thread.currentThread().getThreadGroup();
        ThreadGroup root = currentThreadGroup;
        ThreadGroup parent = root.getParent();
        while (parent != null) {
            root = parent;
            parent = root.getParent();
        }
        showThreadGroup(root, "");
    }

    public static void showThreadGroup(ThreadGroup group, String index) {
        if (group == null) {
            return;
        }
        int count = group.activeCount();
        int countGroup = group.activeGroupCount();
        Thread[] threads = new Thread[count];
        ThreadGroup[] groups = new ThreadGroup[countGroup];
        group.enumerate(threads, false);
        group.enumerate(groups, false);

        for (int i = 0; i < count; ++i) {
            showThread(threads[i], index + "  ");
        }
        for (int i = 0; i < countGroup; ++i) {
            showThreadGroup(groups[i], index + "  ");
        }

    }

    public static void showThread(Thread thread, String index) {
        if (thread == null) {
            return;
        }
    }

    public static void threadsStackTrace() {
        for (Map.Entry<Thread, StackTraceElement[]> entry
                : Thread.getAllStackTraces().entrySet()) {
            Thread thread = entry.getKey();
            StackTraceElement[] stackTraceElements = entry.getValue();
            if (thread.equals(Thread.currentThread())) {
                continue;
            }

        }
    }

    public static void currentThread() {
        Thread thread = Thread.currentThread();
        BA.Log(thread.getId() + " " + thread.getName() + " " + thread.getState());
        for (StackTraceElement element : thread.getStackTrace()) {
            BA.LogError(element.toString());
        }
    }

    public static long getAvaliableMemory() {
        Runtime r = Runtime.getRuntime();
        return r.maxMemory() - (r.totalMemory() - r.freeMemory());
    }

    public static long getAvaliableMemoryMB() {
        return getAvaliableMemory() / (1024 * 1024L);
    }

    public static Point getMousePoint() {
        return MouseInfo.getPointerInfo().getLocation();
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

    public static byte[] MD5(byte[] bytes) {
        return messageDigest(bytes, "MD5");
    }

    public static byte[] SHA1(byte[] bytes) {
        return messageDigest(bytes, "SHA-1");
    }

    public static byte[] SHA256(byte[] bytes) {
        return messageDigest(bytes, "SHA-256");
    }

    public static byte[] MD5(File file) {
        return messageDigest(file, "MD5");
    }

    public static byte[] SHA1(File file) {
        return messageDigest(file, "SHA-1");
    }

    public static byte[] SHA256(File file) {
        return messageDigest(file, "SHA-256");
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

    public static byte[] messageDigest(File file, String algorithm) {
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

    public static SSLServerSocket getDefaultSSLServerSocket() {
        try {
            SSLServerSocketFactory ssl = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            return (SSLServerSocket) ssl.createServerSocket();
        } catch (Exception e) {
            return null;
        }

    }

    public static void SSLServerSocketInfo() {
        try {
            SSLServerSocket sslServerSocket;
            SSLServerSocketFactory ssl = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            sslServerSocket = (SSLServerSocket) ssl.createServerSocket();

            String[] cipherSuites = sslServerSocket.getSupportedCipherSuites();
            for (String suite : cipherSuites) {
                BA.Log(suite);
            }

            String[] protocols = sslServerSocket.getSupportedProtocols();
            for (String protocol : protocols) {
                BA.Log(protocol);
            }
        } catch (Exception e) {

        }

    }
    
}
