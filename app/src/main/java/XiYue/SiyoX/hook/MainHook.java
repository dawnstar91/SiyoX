package XiYue.SiyoX.hook;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.os.Build;
import android.text.TextUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import XiYue.SiyoX.SiyoXConfig;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "SiyoX";

    // 你自己的模块包名(用于反检测屏蔽)
    private static final String MODULE_PACKAGE = "XiYue.SiyoX";

    // 游戏入口 Activity(网易我的世界)
    private static final String GAME_ACTIVITY = "com.mojang.minecraftpe.MainActivity";

    // 网易加固壳
    private static final String STUB_APP = "com.netease.android.protect.StubApp";

    // 你的 native 库名(不带 lib 前缀和 .so)
    private static final String NATIVE_LIB = "siyox";

    private boolean isLoaded = false;
    private boolean activityHooked = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {

        XposedBridge.log("[" + TAG + "] LOADED pkg=" + lpparam.packageName
                + " process=" + lpparam.processName);

        // =========================================================
        // 1. 屏蔽 Pangle(字节)加固的 FileProvider attachInfo
        // =========================================================
        try {
            XposedHelpers.findAndHookMethod(
                    "com.bytedance.pangle.FileProvider",
                    lpparam.classLoader,
                    "attachInfo",
                    Context.class, ProviderInfo.class,
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            return null;
                        }
                    });
        } catch (Throwable ignored) {}

        // =========================================================
        // 2. 关键:拦截网易加固壳 StubApp#attachBaseContext
        //    从壳里拿到真实的游戏 ClassLoader,然后 hook 游戏 Activity
        // =========================================================
        try {
            XposedHelpers.findAndHookMethod(
                    STUB_APP,
                    lpparam.classLoader,
                    "attachBaseContext",
                    Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Context ctx = (Context) param.args[0];
                            if (ctx == null) return;
                            ClassLoader realCl = ctx.getClassLoader();
                            XposedBridge.log("[" + TAG + "] StubApp attached, realCl=" + realCl);
                            hookGameActivity(realCl, ctx);
                        }
                    });
            XposedBridge.log("[" + TAG + "] StubApp hook installed");
        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] StubApp hook failed: " + t);
        }

        // =========================================================
        // 3. 兜底:直接尝试用 lpparam.classLoader hook 游戏 Activity
        //    (有些版本加固壳已加载完,直接能拿到)
        // =========================================================
        try {
            hookGameActivity(lpparam.classLoader, null);
        } catch (Throwable ignored) {}

        // =========================================================
        // 4. 反检测:屏蔽 Class.forName 对我们模块 / LSPatch 的探测
        // =========================================================
        try {
            XposedHelpers.findAndHookMethod(
                    Class.class, "forName",
                    String.class, boolean.class, ClassLoader.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = (String) param.args[0];
                            if (name == null) return;
                            if (name.contains(MODULE_PACKAGE)
                                    || name.contains("org.lsposed.lspatch")
                                    || name.contains("org.lsposed.npatch")
                                    || name.contains("org.lsposed.onpatch")
                                    || name.contains("org.lsposed.opatch")) {
                                param.setThrowable(new ClassNotFoundException());
                            }
                        }
                    });
        } catch (Throwable ignored) {}

        // =========================================================
        // 5. 反检测:过滤 getInstalledPackages / getInstalledApplications
        // =========================================================
        try {
            XposedHelpers.findAndHookMethod(
                    "android.app.ApplicationPackageManager",
                    lpparam.classLoader,
                    "getInstalledApplications",
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            filterAppInfoList((List<?>) param.getResult());
                        }
                    });

            XposedHelpers.findAndHookMethod(
                    "android.app.ApplicationPackageManager",
                    lpparam.classLoader,
                    "getInstalledPackages",
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            filterPackageInfoList((List<?>) param.getResult());
                        }
                    });
        } catch (Throwable ignored) {}

        // =========================================================
        // 6. 针对网易我的世界进程做额外处理
        // =========================================================
        if ("com.netease.x19".equals(lpparam.packageName)
                || "com.ycxbox.mc".equals(lpparam.packageName)) {

            // 检查 libminecraftpe.so 是否在目标 nativeLibraryDir 里
            if (lpparam.appInfo != null
                    && !TextUtils.isEmpty(lpparam.appInfo.nativeLibraryDir)
                    && TextUtils.equals(lpparam.packageName, lpparam.processName)
                    && new File(lpparam.appInfo.nativeLibraryDir, "libminecraftpe.so").exists()) {

                // 反检测:UniSDK 的一个方法返回值里把 .com 换回 .dev
                try {
                    XposedBridge.hookMethod(
                            lpparam.classLoader
                                    .loadClass("com.netease.ntunisdk.unifix.UniFixBase")
                                    .getDeclaredMethod("a", Context.class),
                            new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) {
                                    String str = (String) param.getResult();
                                    if (str != null) {
                                        param.setResult(str.replace(".com", ".dev"));
                                    }
                                }
                            });
                } catch (Throwable ignored) {}
            }
        }
    }

    // ============================================================
    //  用真实 ClassLoader hook 游戏 Activity
    // ============================================================
    private void hookGameActivity(ClassLoader cl, Context ctx) {
        if (activityHooked) return;
        try {
            XposedHelpers.findAndHookMethod(
                    GAME_ACTIVITY, cl, "onResume",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (isLoaded) return;
                            Activity activity = (Activity) param.thisObject;
                            if (activity == null) return;

                            XposedBridge.log("[" + TAG + "] >>> GameActivity onResume HIT");
                            isLoaded = true;

                            // 1. 加载 native SO
                            loadNative(activity);

                            // 2. 后续业务:显示浮窗等
                            // ViewLoader.Loading(activity);
                        }
                    });
            activityHooked = true;
            XposedBridge.log("[" + TAG + "] GameActivity hooked");
        } catch (Throwable t) {
            // 游戏类还没加载时失败是正常的,等 StubApp 回调再试
            XposedBridge.log("[" + TAG + "] hookGameActivity failed (will retry): " + t);
        }
    }

    // ============================================================
    //  加载 native SO
    //  免 Root 环境下,SO 在模块 APK 里,必须解压到目标 App 私有目录再 load
    // ============================================================
    private void loadNative(Context targetCtx) {
        try {
            // 1. 拿 ABI
            String abi = "arm64-v8a";
            if (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
                abi = Build.SUPPORTED_ABIS[0];
            }

            // 2. 目标路径:目标 App 的私有目录
            File outSo = new File(targetCtx.getCacheDir(), "lib" + NATIVE_LIB + ".so");

            // 3. 从模块 APK 里解压 SO
            if (!outSo.exists() || outSo.length() == 0) {
                String moduleApk = findModuleApk();
                XposedBridge.log("[" + TAG + "] moduleApk=" + moduleApk);
                if (moduleApk == null) {
                    XposedBridge.log("[" + TAG + "] 找不到模块 APK");
                    return;
                }
                String entry = "lib/" + abi + "/lib" + NATIVE_LIB + ".so";
                extractFromApk(moduleApk, entry, outSo);
                outSo.setReadable(true, false);
                outSo.setExecutable(true, false);
            }

            XposedBridge.log("[" + TAG + "] loading so: " + outSo
                    + " size=" + outSo.length());

            // 4. 加载
            System.load(outSo.getAbsolutePath());
            XposedBridge.log("[" + TAG + "] native loaded OK");

        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] loadNative failed: " + t);
            t.printStackTrace();
        }
    }

    // ============================================================
    //  找到模块自己 APK 的路径
    // ============================================================
    private String findModuleApk() {
        try {
            java.lang.reflect.Field f = ClassLoader.class.getDeclaredField("pathList");
            f.setAccessible(true);
            Object pathList = f.get(MainHook.class.getClassLoader());
            java.lang.reflect.Field de = pathList.getClass().getDeclaredField("dexElements");
            de.setAccessible(true);
            Object[] elements = (Object[]) de.get(pathList);
            for (Object el : elements) {
                java.lang.reflect.Field df = el.getClass().getDeclaredField("dexFile");
                df.setAccessible(true);
                Object dex = df.get(el);
                if (dex == null) continue;
                String p = dex.toString();
                if (p.contains(MODULE_PACKAGE) || p.contains("SiyoX")) {
                    return p.split(":")[0];
                }
            }
        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] findModuleApk failed: " + t);
        }
        return null;
    }

    // ============================================================
    //  从 APK 里解压某个 entry 到目标文件
    // ============================================================
    private void extractFromApk(String apkPath, String entryName, File outFile) throws Exception {
        ZipFile zip = new ZipFile(apkPath);
        try {
            ZipEntry entry = zip.getEntry(entryName);
            if (entry == null) {
                throw new RuntimeException("entry not found: " + entryName);
            }
            InputStream is = zip.getInputStream(entry);
            FileOutputStream os = new FileOutputStream(outFile);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) > 0) os.write(buf, 0, n);
            } finally {
                try { os.close(); } catch (Throwable ignored) {}
                try { is.close(); } catch (Throwable ignored) {}
            }
        } finally {
            try { zip.close(); } catch (Throwable ignored) {}
        }
    }

    // ============================================================
    //  反检测过滤工具
    // ============================================================
    private void filterAppInfoList(List<?> list) {
        if (list == null) return;
        Iterator<?> it = list.iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (!(o instanceof ApplicationInfo)) continue;
            String pkg = ((ApplicationInfo) o).packageName;
            if (isSuspiciousPackage(pkg)) it.remove();
        }
    }

    private void filterPackageInfoList(List<?> list) {
        if (list == null) return;
        Iterator<?> it = list.iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (!(o instanceof PackageInfo)) continue;
            String pkg = ((PackageInfo) o).packageName;
            if (isSuspiciousPackage(pkg)) it.remove();
        }
    }

    private boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) return false;
        return pkg.equals(MODULE_PACKAGE)
                || pkg.equals("org.lsposed.lspatch")
                || pkg.equals("org.lsposed.npatch")
                || pkg.equals("org.lsposed.onpatch")
                || pkg.equals("org.lsposed.opatch");
    }
}
