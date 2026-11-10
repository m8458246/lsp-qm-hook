package com.eta.qmhook;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "QMHOOK";
    private static final String PKG = "com.kmxs.reader";

    private static void log(String s) {
        Log.i(TAG, s);
        XposedBridge.log(TAG + " " + s);
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

        hookAll(lpparam.classLoader, "com.km.qimao.qmsdk.tools.encryption.Encryption", "sign");
        hookAll(lpparam.classLoader, "com.km.qimao.qmsdk.tools.encryption.Encryption", "encrypt");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "decrypt");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "decryptV2");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "encrypt");
        hookAll(lpparam.classLoader, "com.km.encryption.api.Security", "encryptV2");
        hookAll(lpparam.classLoader, "com.km.encryption.aes.AESManager", "decrypt");
        hookAll(lpparam.classLoader, "com.km.encryption.aes.AESManager", "encrypt");
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
                        for (Object a : p.args) sb.append(trunc(a, 200)).append(" , ");
                        log("IN  " + shortCls + "." + m.getName() + "(" + sb + ")");
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        log("OUT " + m.getName() + " => " + trunc(p.getResult(), 300));
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
