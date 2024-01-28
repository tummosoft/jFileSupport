package com.tummosoft;

import anywheresoftware.b4a.BA;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.math.RoundingMode;
import java.text.NumberFormat;
import java.util.Random;

@BA.ShortName("jDoubleSupport")
public class jDoubleSupport {
    public static double scale3(double invalue) {
        return jDoubleSupport.scale(invalue, 3);
    }

    public static double scale2(double invalue) {
        return jDoubleSupport.scale(invalue, 2);
    }

    public static double scale6(double invalue) {
        return jDoubleSupport.scale(invalue, 6);
    }

    public static double scale(double v, int scale) {
        BigDecimal b = new BigDecimal(Double.toString(v));
        return scale(b, scale);
    }

    public static double scale(BigDecimal b, int scale) {
        return b.setScale(scale, RoundingMode.HALF_UP).doubleValue();
    }

    public static double[] scale(double[] data, int scale) {
        try {
            if (data == null) {
                return null;
            }
            double[] result = new double[data.length];
            for (int i = 0; i < data.length; ++i) {
                result[i] = scale(data[i], scale);
            }
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public static void sortList(anywheresoftware.b4a.objects.collections.List numbersList) {
        List<Integer> numbers = new ArrayList<Integer>();
         
        for (int i=0; i < numbersList.getSize(); i++) {
            Object obj = numbersList.Get(i);
            if (obj instanceof Integer) {
                numbers.add((Integer) obj);
            }
        }
        
        Collections.sort(numbers, new Comparator<Integer>() {
            @Override
            public int compare(Integer p1, Integer p2) {
                return p1 - p2;
            }
        });
    }

    public static double[] sortArray(double[] numbers) {
        List<Double> list = new ArrayList<>();
        for (double i : numbers) {
            list.add(i);
        }
        Collections.sort(list, new Comparator<Double>() {
            @Override
            public int compare(Double p1, Double p2) {
                return (int) (p1 - p2);
            }
        });
        double[] sorted = new double[numbers.length];
        for (int i = 0; i < list.size(); ++i) {
            sorted[i] = list.get(i);
        }
        return sorted;
    }

    public static double[] array(double x, double y, double z) {
        double[] xyz = new double[3];
        xyz[0] = x;
        xyz[1] = y;
        xyz[2] = z;
        return xyz;
    }
    
   private static NumberFormat numberFormat;
  
    
    public static String percentage(double data, double total) {
        return percentage(data, total, 2);
    }

    public static String percentage(double data, double total, int scale) {
        try {
            if (total == 0) {
                return "Invalid";
            }
            return scale(data * 100 / total, scale) + "";
        } catch (Exception e) {
            return data + "";
        }
    }
    
    // invalid values are counted as smaller
    public static int compare(double d1, double d2, boolean desc) {
        if (Double.isNaN(d1)) {
            if (Double.isNaN(d2)) {
                return 0;
            } else {
                return desc ? 1 : -1;
            }
        } else {
            if (Double.isNaN(d2)) {
                return desc ? -1 : 1;
            } else {
                double diff = d1 - d2;
                if (diff == 0) {
                    return 0;
                } else if (diff > 0) {
                    return desc ? -1 : 1;
                } else {
                    return desc ? 1 : -1;
                }
            }
        }
    }
    
    private static NumberFormat numberFormat2() {
        numberFormat = NumberFormat.getInstance();
        numberFormat.setMinimumFractionDigits(0);
        numberFormat.setGroupingUsed(false);
        numberFormat.setRoundingMode(RoundingMode.HALF_UP);
        return numberFormat;
    }

    public static String scaleString(double v, int scale) {
        try {
            if (scale < 0) {
                return v + "";
            }
            if (numberFormat == null) {
                numberFormat2();
            }
            numberFormat.setMaximumFractionDigits(scale);
            return numberFormat.format(v);
        } catch (Exception e) {
            BA.Log(e.getMessage());
            return v + "";
        }
    }

    public static double random(int max, boolean nonNegative) {
        
        Random r = new Random();
        
        int sign = nonNegative ? 1 : r.nextInt(2);
        sign = sign == 1 ? 1 : -1;
        double d = r.nextDouble();
        int i = max > 0 ? r.nextInt(max) : 0;
        return sign == 1 ? i + d : -(i + d);
    }
}
