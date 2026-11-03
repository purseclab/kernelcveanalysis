/**
 * @name Object database allocations
 * @id cpp/objectdb/allocations
 * @description Exports allocation sites linked directly to CodeQL types.
 * @kind table
 */
import cpp
import kernel_utils
import object_types

from KmallocCall call, Class allocatedType
where allocatedType = call.getStruct()
select sourceLocation(call), call.getTarget().getName(), allocatedType.(ExportType),
  allocatedType.getName(), sourceLocation(allocatedType), objectTypeSize(allocatedType),
  call.getFlag(), call.getSize(), call.isFlexible(), call.getCacheName()
