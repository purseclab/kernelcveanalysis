/**
 * @name Object database types
 * @id cpp/objectdb/types
 * @description Exports type identity, layout, and references from CodeQL.
 * @kind table
 */
import cpp
import object_types

from Type t, int alignment, int elementCount, int isAnon
where
  (if exists(t.getAlignment()) then alignment = t.getAlignment() else alignment = -1) and
  (if exists(t.(ArrayType).getArraySize())
   then elementCount = t.(ArrayType).getArraySize() else elementCount = -1) and
  (if t.(UserType).isAnonymous() then isAnon = 1 else isAnon = 0)
select t.(ExportType), objectTypeName(t), objectTypeKind(t), objectTypeSize(t), alignment,
  referencedType(t).(ExportType), elementCount, sourceLocation(t), isAnon
