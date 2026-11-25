package com.memsweep.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 无第三方依赖的反射工具：所有容器适配都通过本类访问，
 * 保证 agent jar 不编译依赖任何应用服务器类，能在 Tomcat/Jetty/Undertow/WebLogic 等
 * 不同类加载器体系里运行。
 */
public final class Reflect {

    private Reflect() {}

    /** 在对象及其父类链上按字段名查找字段（含私有字段），并强制可访问。 */
    public static Optional<Field> findField(Object target, String name) {
        if (target == null) {
            return Optional.empty();
        }
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return Optional.of(f);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (RuntimeException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public static Object getField(Object target, String name) {
        Optional<Field> f = findField(target, name);
        if (f.isEmpty()) {
            return null;
        }
        try {
            return f.get().get(target);
        } catch (Exception e) {
            return null;
        }
    }

    /** 按类型在对象上取字段（适配不同版本字段名变化）。 */
    public static Object getFieldOfType(Object target, Class<?> type) {
        if (target == null) {
            return null;
        }
        Class<?> c = target.getClass();
        while (c != null) {
            for (Field f : c.getDeclaredFields()) {
                if (type.isAssignableFrom(f.getType())) {
                    try {
                        f.setAccessible(true);
                        return f.get(target);
                    } catch (Exception ignored) {
                    }
                }
            }
            c = c.getSuperclass();
        }
        return null;
    }

    public static Object invoke(Object target, String method, Object... args) {
        if (target == null) {
            return null;
        }
        Class<?>[] paramTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            paramTypes[i] = args[i] == null ? null : args[i].getClass();
        }
        Class<?> c = target.getClass();
        while (c != null) {
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(method) || m.getParameterCount() != args.length) {
                    continue;
                }
                if (paramsMatch(m.getParameterTypes(), paramTypes, args)) {
                    try {
                        m.setAccessible(true);
                        return m.invoke(target, args);
                    } catch (Exception e) {
                        return null;
                    }
                }
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private static boolean paramsMatch(Class<?>[] declared, Class<?>[] actual, Object[] args) {
        for (int i = 0; i < declared.length; i++) {
            if (args[i] == null) {
                if (declared[i].isPrimitive()) {
                    return false;
                }
            } else if (!wrap(declared[i]).isAssignableFrom(wrap(actual[i]))) {
                return false;
            }
        }
        return true;
    }

    private static Class<?> wrap(Class<?> c) {
        if (!c.isPrimitive()) {
            return c;
        }
        if (c == int.class) return Integer.class;
        if (c == long.class) return Long.class;
        if (c == boolean.class) return Boolean.class;
        if (c == byte.class) return Byte.class;
        if (c == char.class) return Character.class;
        if (c == short.class) return Short.class;
        if (c == float.class) return Float.class;
        if (c == double.class) return Double.class;
        return c;
    }

    /** 按简单类名在类层次上查找方法（跨 jakarta/javax 命名空间时使用）。 */
    public static Optional<Method> findMethodByName(Class<?> c, String name) {
        while (c != null) {
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(name)) {
                    m.setAccessible(true);
                    return Optional.of(m);
                }
            }
            c = c.getSuperclass();
        }
        return Optional.empty();
    }

    public static Object invokeMethod(Method m, Object target, Object... args) {
        try {
            m.setAccessible(true);
            return m.invoke(target, args);
        } catch (Exception e) {
            return null;
        }
    }

    public static String safeName(Object o) {
        return o == null ? "null" : o.getClass().getName();
    }

    public static List<Field> allFields(Class<?> c) {
        List<Field> out = new ArrayList<>();
        while (c != null) {
            for (Field f : c.getDeclaredFields()) {
                try {
                    f.setAccessible(true);
                    out.add(f);
                } catch (RuntimeException ignored) {
                }
            }
            c = c.getSuperclass();
        }
        return out;
    }

    /** 判断对象的类是否匹配给定全限定名（避免直接 Class.forName 触发类加载器问题）。 */
    public static boolean classNameMatches(Object o, String fqcn) {
        return o != null && o.getClass().getName().equals(fqcn);
    }

    public static Set<Class<?>> typeHierarchy(Class<?> c) {
        Set<Class<?>> out = new LinkedHashSet<>();
        while (c != null) {
            out.add(c);
            out.addAll(Arrays.asList(c.getInterfaces()));
            c = c.getSuperclass();
        }
        return out;
    }

    /** 判断类是否实现/继承给定简单名的类型（按名称匹配，适配 javax 与 jakarta 两套包名）。 */
    public static boolean implementsSimpleName(Class<?> c, String simpleName) {
        for (Class<?> t : typeHierarchy(c)) {
            if (t.getSimpleName().equals(simpleName)) {
                return true;
            }
            for (Class<?> i : t.getInterfaces()) {
                if (i.getSimpleName().equals(simpleName)) {
                    return true;
                }
            }
        }
        return false;
    }
}
