using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// Metadata only: never Assembly.Load, GetType, or invoke any target code here.
sealed class Types : ISignatureTypeProvider<string, object>
{
    public string GetPrimitiveType(PrimitiveTypeCode t) => t.ToString();
    public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte k) => "type:" + r.GetString(r.GetTypeDefinition(h).Name);
    public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte k) => "ref:" + r.GetString(r.GetTypeReference(h).Name);
    public string GetTypeFromSpecification(MetadataReader r, object c, TypeSpecificationHandle h, byte k) => "spec";
    public string GetSZArrayType(string t) => "array:" + t;
    public string GetArrayType(string t, ArrayShape s) => "array:" + t;
    public string GetByReferenceType(string t) => "byref:" + t;
    public string GetPointerType(string t) => "ptr:" + t;
    public string GetPinnedType(string t) => "pinned:" + t;
    public string GetModifiedType(string m, string t, bool required) => "modified:" + t;
    public string GetGenericInstantiation(string t, ImmutableArray<string> a) => "generic:" + t;
    public string GetGenericMethodParameter(object c, int i) => "method-generic";
    public string GetGenericTypeParameter(object c, int i) => "type-generic";
    public string GetFunctionPointerType(MethodSignature<string> s) => "function-pointer";
}

static class Program
{
    static string TypeName(MetadataReader r, TypeDefinitionHandle h)
    {
        var t = r.GetTypeDefinition(h);
        var parent = t.GetDeclaringType();
        string name = r.GetString(t.Name);
        if (!parent.IsNil) return TypeName(r, parent) + "+" + name;
        string ns = r.GetString(t.Namespace);
        return ns.Length == 0 ? name : ns + "." + name;
    }

    static int Main(string[] args)
    {
        if (args.Length != 1) throw new ArgumentException("one assembly path required");
        using var file = File.OpenRead(args[0]);
        using var pe = new PEReader(file);
        var reader = pe.GetMetadataReader();
        var types = new Types();
        var methods = new List<object>();
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            foreach (var handle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(handle);
                var signature = method.DecodeSignature(types, (object)null);
                MethodBodyBlock body = method.RelativeVirtualAddress == 0 ? null : pe.GetMethodBody(method.RelativeVirtualAddress);
                var locals = body == null || body.LocalSignature.IsNil ? ImmutableArray<string>.Empty :
                    reader.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(types, (object)null);
                methods.Add(new {
                    type = TypeName(reader, typeHandle), name = reader.GetString(method.Name),
                    token = System.Reflection.Metadata.Ecma335.MetadataTokens.GetToken(handle),
                    is_static = (method.Attributes & MethodAttributes.Static) != 0,
                    is_public = (method.Attributes & MethodAttributes.MemberAccessMask) == MethodAttributes.Public,
                    generic_count = method.GetGenericParameters().Count + type.GetGenericParameters().Count,
                    calling_convention = signature.Header.CallingConvention.ToString(),
                    return_type = signature.ReturnType, parameters = signature.ParameterTypes,
                    locals = locals, init_locals = body?.LocalVariablesInitialized ?? false,
                    max_stack = body?.MaxStack ?? 0, exception_regions = body?.ExceptionRegions.Length ?? 0,
                    il = body == null ? null : Convert.ToBase64String(body.GetILBytes())
                });
            }
        }
        var opcodes = new Dictionary<string, object>();
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode op)
                opcodes[unchecked((ushort)op.Value).ToString()] = new { name = op.Name, operand = op.OperandType.ToString() };
        }
        Console.Write(JsonSerializer.Serialize(new { schema_version = 1, methods = methods, opcodes = opcodes }));
        return 0;
    }
}
