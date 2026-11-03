import cpp

// Export database-local identity without Element's source links or cached labels.
// Selecting Type/Class directly also evaluates their inherited presentation
// predicates, even when bqrs decode later requests only IDs.
class ExportType extends @type {
  string toString() { result = "" }
}

string objectTypeName(Type t) {
  if exists(t.getName()) then result = t.getName() else result = "<unknown>"
}

// Keep identity as an ExportType entity, with explicit scalar metadata columns.
string objectTypeKind(Type t) {
  if t instanceof Union then result = "UNION"
  else if t instanceof Struct or t instanceof Class then result = "STRUCT"
  else if t instanceof PointerType or t instanceof FunctionPointerType then result = "PTR"
  else if t instanceof ArrayType then result = "ARRAY"
  else if t instanceof TypedefType then result = "TYPEDEF"
  else if t instanceof SpecifiedType then result = "QUALIFIED"
  else if t instanceof RoutineType then result = "FUNC_PROTO"
  else if t instanceof Enum then result = "ENUM"
  else if t instanceof IntegralType then result = "INT"
  else if t instanceof FloatingPointType then result = "FLOAT"
  else if t instanceof VoidType then result = "VOID"
  else result = "OTHER"
}

Type referencedType(Type t) {
  if t instanceof DerivedType then result = t.(DerivedType).getBaseType()
  else if t instanceof TypedefType then result = t.(TypedefType).getBaseType()
  else result = t
}

int objectTypeSize(Type t) {
  if exists(t.getSize()) then result = t.getSize() else result = -1
}

private string sourceLocationCandidate(Locatable element) {
  if exists(element.getLocation().getFile().getRelativePath())
  then
    exists(Location loc | loc = element.getLocation() |
      result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" +
        loc.getStartColumn().toString() + ":" + loc.getEndLine().toString() + ":" +
        loc.getEndColumn().toString()
    )
  else result = ""
}

// CodeQL can resolve several declarations to one entity. Location is only a
// representative display value; it must not multiply exported type identities.
string sourceLocation(Locatable element) {
  result = min(sourceLocationCandidate(element))
}
