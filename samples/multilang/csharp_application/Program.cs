using System;

namespace Sample;

// Console UI; UNSELECTED. Parses two integers and prints the pipeline result.
// This file must remain byte-identical after integration: it is the "caller/UI"
// that keeps invoking the same public API.
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("usage: app <seed> <rounds>");
            return 2;
        }

        int seed = int.Parse(args[0]);
        int rounds = int.Parse(args[1]);
        long result = Ops.Pipeline(seed, rounds);
        Console.WriteLine(result.ToString());
        return 0;
    }
}
