using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;

// Explicit reference-evaluation helper, never called by metadata inspection/build.
static class Program
{
    static int Main(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("assembly and method token required");
        var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
        var method = (MethodInfo)assembly.ManifestModule.ResolveMethod(int.Parse(args[1], CultureInfo.InvariantCulture));
        var parameters = method.GetParameters();
        string line;
        while ((line = Console.ReadLine()) != null)
        {
            var values = JsonSerializer.Deserialize<string[]>(line);
            if (values.Length != parameters.Length) throw new ArgumentException("argument count");
            var converted = new object[values.Length];
            for (int i = 0; i < values.Length; i++)
                converted[i] = Convert.ChangeType(values[i], parameters[i].ParameterType, CultureInfo.InvariantCulture);
            object result = method.Invoke(null, converted);
            Console.WriteLine(Convert.ToString(result, CultureInfo.InvariantCulture));
        }
        return 0;
    }
}
