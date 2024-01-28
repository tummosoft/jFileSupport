package com.tummosoft;

import anywheresoftware.b4a.BA;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

@BA.ShortName("jByteSupport")
public class jByteSupport {
     private static int Invalid_Byte = -999;
     
      public enum Line_Break {
        LF, // Liunx/Unix
        CR, // IOS
        CRLF, // Windows
        Width,
        Value,
        Auto
    }
     
    //  Big-Endian
    public static int bytesToInt(byte[] b) {
        return b[3] & 0xFF
                | (b[2] & 0xFF) << 8
                | (b[1] & 0xFF) << 16
                | (b[0] & 0xFF) << 24;
    }

    public static int bytesToUshort(byte[] b) {
        return b[1] & 0xFF
                | (b[0] & 0xFF) << 8;
    }

    public static byte[] intToBytes(int a) {
        return new byte[]{
            (byte) ((a >> 24) & 0xFF),
            (byte) ((a >> 16) & 0xFF),
            (byte) ((a >> 8) & 0xFF),
            (byte) (a & 0xFF)
        };
    }

    public static byte intSmallByte(int a) {
        byte[] bytes = intToBytes(a);
        return bytes[3];
    }

    public static byte intBigByte(int a) {
        byte[] bytes = intToBytes(a);
        return bytes[0];
    }

    public static byte[] unsignedShortToBytes(int s) {
        return new byte[]{
            (byte) ((s >>> 8) & 0xFF),
            (byte) (s & 0xFF)
        };
    }

    public static byte[] shortToBytes(short s) {
        return new byte[]{
            (byte) ((s >> 8) & 0xFF),
            (byte) (s & 0xFF)
        };
    }

    public static String byteToHex(byte b) {
        String hex = Integer.toHexString(b & 0xFF);
        if (hex.length() < 2) {
            hex = "0" + hex;
        }
        return hex;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; ++i) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    public static String stringToHexFormat(String text) {
        return bytesToHexFormatWithCF2(text.getBytes());
    }

    private static String bytesToHexFormatWithCF2(byte[] bytes) {
        return bytesToHexFormatWithCF3(bytes, bytesToHex("\n".getBytes()));
    }

   private static String bytesToHexFormatWithCF3(byte[] bytes, String newLineHex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; ++i) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex).append(" ");
        }
        String s = sb.toString();
        s = s.replace(newLineHex + " ", newLineHex + "\n");
        s = s.toUpperCase();
        return s;
    }

//    public static String bytesToHexFormat(byte[] bytes, String newLineValue) {
//        String s = bytesToHexFormat(bytes);
//        s = s.replace("\n", newLineHex.trim() + "\n");
//        logger.debug(newLineHex);
//        return s;
//    }
    public static String bytesToHexFormat(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; ++i) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex).append(" ");
        }
        String s = sb.toString();
        s = s.toUpperCase();
        return s;
    }

    public static String bytesToHexFormat2(byte[] bytes, int newLineWidth) {
        StringBuilder sb = new StringBuilder();
        int count = 1;
        for (int i = 0; i < bytes.length; ++i) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex).append(" ");
            if (count % newLineWidth == 0) {
                sb.append("\n");
            }
            count++;
        }
        String s = sb.toString();
        s = s.toUpperCase();
        return s;
    }

    public static byte[] hexToBytes(String inHex) {
        try {
            int hexlen = inHex.length();
            byte[] result;
            if (hexlen % 2 == 1) {
                hexlen++;
                result = new byte[(hexlen / 2)];
                inHex = "0" + inHex;
            } else {
                result = new byte[(hexlen / 2)];
            }
            int j = 0;
            for (int i = 0; i < hexlen; i += 2) {
                result[j] = hexToByte(inHex.substring(i, i + 2));
                j++;
            }
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte hexToByte(String inHex) {
        try {
            return (byte) Integer.parseInt(inHex, 16);
        } catch (Exception e) {
            return 0;
        }
    }

    public static byte hexToByteAnyway(String inHex) {
        try {
            return (byte) Integer.parseInt(inHex, 16);
        } catch (Exception e) {
            return Byte.valueOf("63");// "?"
        }
    }

    public static int hexToInt(String inHex) {
        try {
            if (inHex.length() == 0 || inHex.length() > 2) {
                return Invalid_Byte;
            }
            String hex = inHex;
            if (inHex.length() == 1) {
                hex = "0" + hex;
            }
            return Integer.parseInt(hex, 16);
        } catch (Exception e) {
            return Invalid_Byte;
        }
    }

    public static String validateByteHex(String inHex) {
        try {
            if (inHex.length() == 0 || inHex.length() > 2) {
                return null;
            }
            String hex = inHex;
            if (inHex.length() == 1) {
                hex = "0" + hex;
            }
            Integer.parseInt(hex, 16);
            return hex;
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isByteHex(String inHex) {
        try {
            if (inHex.length() != 2) {
                return false;
            }
            Integer.parseInt(inHex, 16);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isBytesHex(String inHex) {
        try {
            int hexlen = inHex.length();
            if (hexlen % 2 == 1) {
                return false;
            }
            for (int i = 0; i < hexlen; i += 2) {
                Integer.parseInt(inHex.substring(i, i + 2), 16);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static String validateTextHex(String text) {
        try {
            String inHex = text.replaceAll(" ", "").replaceAll("\n", "").toUpperCase();
            int hexlen = inHex.length();
            if (hexlen % 2 == 1) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            String b;
            for (int i = 0; i < hexlen; i += 2) {
                b = inHex.substring(i, i + 2);
                Integer.parseInt(b, 16);
                sb.append(b).append(" ");
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] hexToBytesAnyway(String inHex) {
        try {
            int hexlen = inHex.length();
            byte[] result;
            if (hexlen % 2 == 1) {
                hexlen++;
                result = new byte[(hexlen / 2)];
                inHex = "0" + inHex;
            } else {
                result = new byte[(hexlen / 2)];
            }
            int j = 0;
            for (int i = 0; i < hexlen; i += 2) {
                result[j] = hexToByteAnyway(inHex.substring(i, i + 2));
                j++;
            }
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] hexFormatToBytes(String hexFormat) {
        String hex = hexFormat.replaceAll(" ", "").replaceAll("\n", "");
        return hexToBytesAnyway(hex);
    }

    public static byte[] subBytes(byte[] bytes, int off, int length) {
        try {
            byte[] newBytes = new byte[length];
            System.arraycopy(bytes, off, newBytes, 0, length);
            return newBytes;
        } catch (Exception e) {
            
            BA.LogError(bytes.length + " " + off + " " + length);
            BA.LogError(e.toString());
            return null;
        }
    }

    public static byte[] mergeBytes(byte[] bytes1, byte[] bytes2) {
        try {
            byte[] bytes3 = new byte[bytes1.length + bytes2.length];
            System.arraycopy(bytes1, 0, bytes3, 0, bytes1.length);
            System.arraycopy(bytes2, 0, bytes3, bytes1.length, bytes2.length);
            return bytes3;
        } catch (Exception e) {
            BA.LogError(e.toString());
            return null;
        }
    }
    
    public static int lineIndex(String lineText, Charset charset, int offset) {
        int hIndex = 0;
        byte[] cBytes;
        for (int i = 0; i < lineText.length(); ++i) {
            char c = lineText.charAt(i);
            cBytes = String.valueOf(c).getBytes(charset);
            int clen = cBytes.length * 3;
            if (offset <= hIndex + clen) {
                return i;
            }
            hIndex += clen;
        }
        return -1;
    }
    

    public static int indexOf(String hexString, String hexSubString, int initFrom) {
        if (hexString == null || hexSubString == null
                || hexString.length() < hexSubString.length()) {
            return -1;
        }
        int from = initFrom, pos = 0;
        while (pos >= 0) {
            pos = hexString.indexOf(hexSubString, from);
            if (pos % 2 == 0) {
                return pos;
            }
            from = pos + 1;
        }
        return -1;
    }
    
      /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param   hex         the hex string
     * @return              the hex string decoded into a byte array
     */
	public static byte[] GetByteFromHex(String hex)
    {
        byte[] binary = new byte[hex.length() / 2];
        for(int i = 0; i < binary.length; i++)
        {
            binary[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return binary;
    }
 
    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param   array       the byte array to convert
     * @return              a length*2 character string encoding the byte array
     */
    public static String BytestoHex2(byte[] array)
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
            return String.format("%0" + paddingLength + "d", 0) + hex;
        else
            return hex;
    }
    
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }
    
    public int BytesToINT2(byte[] b) {
		int len;
		len = 256 * ByteToINT(b[0]) + ByteToINT(b[1]);
		return len;
	}

	public int ByteToINT(byte b) {
		if (b < 0)
			return 256 + b;
		return b;
	}

	public byte[] IntToBytes2(int len) {
		byte[] b = new byte[2];
		b[0] = (byte) (len / 256);
		b[1] = (byte) (len % 256);
		return b;
	}
    
    
    public static String formatHex(String hexString,
            Line_Break lineBreak, int lineBreakWidth, String lineBreakValue) {
        String text = hexString;
        if (lineBreak == Line_Break.Width && lineBreakWidth > 0) {
            int step = 3 * lineBreakWidth;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < text.length(); i += step) {
                if (i + step < text.length()) {
                    sb.append(text.substring(i, i + step - 1)).append("\n");
                } else {
                    sb.append(text.substring(i, text.length() - 1));
                }
            }
            text = sb.toString();
        } else if (lineBreakValue != null) {
            if (text.endsWith(lineBreakValue)) {
                text = text.replaceAll(lineBreakValue, lineBreakValue.trim() + "\n");
                text = text.substring(0, text.length() - 1);
            } else {
                text = text.replaceAll(lineBreakValue, lineBreakValue.trim() + "\n");
            }
        }
        return text;
    }

    public static long checkBytesValue(String string) {
        try {
            String strV = string.trim().toLowerCase();
            long unit = 1;
            if (strV.endsWith("b")) {
                unit = 1;
                strV = strV.substring(0, strV.length() - 1);
            } else if (strV.endsWith("k")) {
                unit = 1024;
                strV = strV.substring(0, strV.length() - 1);
            } else if (strV.endsWith("m")) {
                unit = 1024 * 1024;
                strV = strV.substring(0, strV.length() - 1);
            } else if (strV.endsWith("g")) {
                unit = 1024 * 1024 * 1024L;
                strV = strV.substring(0, strV.length() - 1);
            }
            long v = Integer.valueOf(strV.trim());
            if (v >= 0) {
                return v * unit;
            } else {
                return -1;
            }
        } catch (Exception e) {
            return -1;
        }
    }

    public static byte[] deflate(Object object) {
        return deflate2(ObjectToBytes(object));
    }

    private static byte[] deflate2(byte[] bytes) {
        try {
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            try ( DeflaterOutputStream out = new DeflaterOutputStream(a)) {
                out.write(bytes);
                out.flush();
            }
            return a.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] inflate(Object object) {
        return inflate2(ObjectToBytes(object));
    }

    private static byte[] inflate2(byte[] bytes) {
        try {
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            try ( InflaterOutputStream out = new InflaterOutputStream(a)) {
                out.write(bytes);
                out.flush();
            }
            return a.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] ObjectToBytes(Object object) {
        try {
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            try ( ObjectOutputStream out = new ObjectOutputStream(a)) {
                out.writeObject(object);
                out.flush();
            }
            return a.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static Object BytesToObject(byte[] bytes) {
        try {
            ByteArrayInputStream a = new ByteArrayInputStream(bytes);
            try ( ObjectInputStream in = new ObjectInputStream(a)) {
                return in.readObject();
            }
        } catch (Exception e) {
            return null;
        }
    }
}
