package com.eta.qmhook;

import android.util.Log;

import java.security.MessageDigest;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "QMHOOK";
    private static final String PKG = "com.kmxs.reader";
    private static final String[] KEY_CANDIDATES = {
            "d3dGiJc651gSQ8w1",
            "242ccb8230d709e1",
            "8w1",
            ""
    };

    private static void log(String s) {
        Log.i(TAG, s);
        XposedBridge.log(TAG + " " + s);
    }

    private static String md5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Throwable t) {
            return "ERR";
        }
    }

    private static String trunc(Object o, int n) {
        if (o == null) return "null";
        if (o instanceof byte[]) {
            byte[] b = (byte[]) o;
            StringBuilder sb = new StringBuilder("bytes[").append(b.length).append("]:");
            int lim = Math.min(b.length, n);
            for (int i = 0; i < lim; i++) sb.append(String.format("%02x", b[i]));
            return sb.toString();
        }
        String s = String.valueOf(o);
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!PKG.equals(lpparam.packageName)) return;
        log("loaded pkg=" + lpparam.packageName);

        hookAll(lpparam.classLoader, "com.qimao.qmsdk.tools.encryption.Encryption", "sign");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "decrypt");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "decryptV2");
        hookAll(lpparam.classLoader, "com.km.encryption.aes.AESManager", "decrypt");
    }

    private void hookAll(ClassLoader cl, String cls, String method) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, cl);
            int n = 0;
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(method)) continue;
                final String shortCls = cls.substring(cls.lastIndexOf('.') + 1);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        StringBuilder sb = new StringBuilder();
                        for (Object a : p.args) sb.append(trunc(a, 4000)).append(" , ");
                        log("IN  " + shortCls + "." + m.getName() + "(" + sb + ")");
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        Object res = p.getResult();
                        log("OUT " + m.getName() + " => " + trunc(res, 4000));
                        if ("sign".equals(m.getName()) && res != null && p.args.length > 0) {
                            String in = String.valueOf(p.args[0]);
                            String out = String.valueOf(res);
                            for (String k : KEY_CANDIDATES) {
                                if (md5(in + k).equals(out)) {
                                    log("SIGN KEY MATCH: [" + k + "]");
                                }
                            }
                        }
                    }
                });
                n++;
            }
            log("hooked " + cls + "." + method + " x" + n);
        } catch (Throwable t) {
            log("hook fail " + cls + "." + method + " : " + t);
        }
    }
}
