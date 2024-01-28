package com.tummosoft;

import anywheresoftware.b4a.BA;
import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@BA.ShortName("jStringSupport")
public class jStringSupport {
    public static String[] separatedBySpace(String string) {
        String[] ss = new String[2];
        String s = string.trim();
        int pos1 = s.indexOf(' ');
        if (pos1 < 0) {
            ss[0] = s;
            ss[1] = "";
            return ss;
        }
        ss[0] = s.substring(0, pos1);
        ss[1] = s.substring(pos1).trim();
        return ss;
    }

    public static String[] splitBySpace(String string) {
        String[] splitted = string.trim().split("\\s+");
        return splitted;
    }

    public static String[] splitByComma(String string) {
        String[] splitted = string.split(",");
        return splitted;
    }

    public static String fillLeftZero(int value, int digit) {
        String v = value + "";
        for (int i = v.length(); i < digit; ++i) {
            v = "0" + v;
        }
        return v;
    }

    public static String fillRightZero(int value, int digit) {
        String v = value + "";
        for (int i = v.length(); i < digit; ++i) {
            v += "0";
        }
        return v;
    }

    public static String fillRightBlank(int value, int digit) {
        String v = value + "";
        for (int i = v.length(); i < digit; ++i) {
            v += " ";
        }
        return v;
    }

    public static String fillLeftBlank(int value, int digit) {
        String v = value + "";
        for (int i = v.length(); i < digit; ++i) {
            v = " " + v;
        }
        return v;
    }

    public static String fillRightBlank(double value, int digit) {
        String v = value + "";
        for (int i = v.length(); i < digit; ++i) {
            v += " ";
        }
        return v;
    }

    public static String fillLeftBlank2(double value, int digit) {
        String v = new BigDecimal(value + "").toString() + "";
        for (int i = v.length(); i < digit; ++i) {
            v = " " + v;
        }
        return v;
    }

    public static String fillRightBlank2(String value, int digit) {
        String v = value;
        for (int i = v.length(); i < digit; ++i) {
            v += " ";
        }
        return v;
    }

    public static String format(long data) {
        DecimalFormat df = new DecimalFormat("#,###");
        return df.format(data);
    }

    public static String format2(double data) {
        return format(Math.round(data));
    }

    public static String leftAlgin(String name, String value, int nameLength) {
        return String.format("%-" + nameLength + "s:" + value, name);
    }

    public static String replaceAll(String value, String oldString,
            String newString) {
        if (value == null || value.isEmpty()
                || oldString == null || oldString.isEmpty()
                || newString == null) {
            return value;
        }
        try {
            String replaced = value.replace(
                    oldString.subSequence(0, oldString.length()),
                    newString.subSequence(0, newString.length())
            );
            return replaced;
        } catch (Exception e) {
            //            logger.debug(e.toString());
            return value;
        }
    }
    
    public static boolean match(String value, String regex) {
        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(value);
            return matcher.matches();
        } catch (Exception e) {
            //            logger.debug(e.toString());
            return false;
        }
    }

    public static int lastRegex(String value, String regex) {
        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(value);
            int index = -1;
            while (matcher.find()) {
                index = matcher.start();
            }
            return index;
        } catch (Exception e) {
            //            logger.debug(e.toString());
            return -1;
        }
    }

    public static int firstRegex(String value, String regex) {
        return firstRegex2(value, regex, 0);
    }

    private static int firstRegex2(String value, String regex, int from) {
        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(value);
            if (matcher.find(from)) {
                return matcher.start();
            } else {
                return -1;
            }
        } catch (Exception e) {
            //            logger.debug(e.toString());
            return -1;
        }
    }
    
    public static int countNumberRegex(String value, String regex) {
        if (value == null || value.isEmpty() || regex == null || regex.isEmpty()) {
            return 0;
        }
        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(value);
            int count = 0;
            while (matcher.find()) {
                count++;
            }
            return count;
        } catch (Exception e) {
            //            logger.debug(e.toString());
            return 0;
        }
    }

    private static int countNumber(String value, String subString) {
        if (value == null || value.isEmpty() || subString == null || subString.isEmpty() || value.length() < subString.length()) {
            return 0;
        }
        int fromIndex = 0;
        int count = 0;
        while (true) {
            int index = value.indexOf(subString, fromIndex);
            if (index < 0) {
                break;
            }
            fromIndex = index + 1;
            count++;
        }
        return count;
    }
    
    public static String decodeUnicode(String unicode) {
        if (unicode == null || "".equals(unicode)) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int i, pos = 0;
        while ((i = unicode.indexOf("\\u", pos)) != -1) {
            sb.append(unicode.substring(pos, i));
            if (i + 5 < unicode.length()) {
                pos = i + 6;
                sb.append((char) Integer.parseInt(unicode.substring(i + 2, i + 6), 16));
            } else {
                break;
            }
        }
        return sb.toString();
    }

    public static String encodeUnicode(String value) {
        if (value == null || "".equals(value)) {
            return null;
        }
        StringBuilder unicode = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            unicode.append("\\u").append(Integer.toHexString(c));
        }
        return unicode.toString();
    }
}
