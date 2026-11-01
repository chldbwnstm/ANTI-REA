import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;

/** Explicit trusted-source reference evaluator. Never used by inspection/build. */
public final class ReferenceRunner {
    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !args[2].matches("\\([IJ]{0,8}\\)[IJ]"))
            throw new IllegalArgumentException("class, method, scalar descriptor required");
        String signature = args[2];
        int count = signature.indexOf(')') - 1;
        Class<?>[] types = new Class<?>[count];
        for (int i = 0; i < count; i++) types[i] = signature.charAt(i+1) == 'I' ? int.class : long.class;
        Class<?> target = Class.forName(args[0]);
        Method method = target.getDeclaredMethod(args[1], types);
        if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers()) ||
            method.getReturnType() != (signature.charAt(signature.length()-1) == 'I' ? int.class : long.class))
            throw new IllegalArgumentException("method ABI mismatch");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = reader.readLine()) != null;) {
            String[] words = line.isEmpty() ? new String[0] : line.split(" ", -1);
            if (words.length != count) throw new IllegalArgumentException("argument count");
            Object[] values = new Object[count];
            for (int i = 0; i < count; i++) {
                // Do not use numeric conditional boxing (which promotes int to long).
                if (types[i] == int.class) values[i] = Integer.valueOf(words[i]);
                else values[i] = Long.valueOf(words[i]);
            }
            System.out.println(method.invoke(null, values));
        }
    }
}
