/**
 * @name Object database named cache allocations
 * @id cpp/objectdb/named-cache-allocations
 * @description Exports allocation sites with a resolved named cache.
 * @kind table
 */
import cpp
import kernel_utils
import object_types

from KmallocCall call, Class allocatedType
where allocatedType = call.getStruct() and call.getCacheName() != "default"
select sourceLocation(call), call.getTarget().getName(), allocatedType.(ExportType),
  allocatedType.getName(), sourceLocation(allocatedType), objectTypeSize(allocatedType),
  call.getFlag(), call.getSize(), call.isFlexible(), call.getCacheName()
