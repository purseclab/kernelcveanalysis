/**
 * @name Object database fields
 * @id cpp/objectdb/fields
 * @description Exports members, including overlapping union fields and bitfields.
 * @kind table
 */
import cpp
import object_types

string memberName(MemberVariable field) {
  // CodeQL gives anonymous embedded records this synthetic member name.
  if field.hasName("(unknown field)") then result = "" else result = field.getName()
}

int memberByteOffset(MemberVariable field) {
  if exists(field.(Field).getByteOffset())
  then result = field.(Field).getByteOffset() else result = -1
}

int memberBitOffset(MemberVariable field) {
  if exists(field.(BitField).getBitOffset())
  then result = field.(BitField).getBitOffset()
  else if field instanceof Field and not field instanceof BitField then result = 0
  else result = -1
}

int memberBitSize(MemberVariable field) {
  if exists(field.(BitField).getNumBits())
  then result = field.(BitField).getNumBits()
  else if field instanceof Field and not field instanceof BitField then result = 0
  else result = -1
}

from Class owner, MemberVariable field, int index
where field = owner.getCanonicalMember(index) and not field.isStatic()
select owner.(ExportType), index, memberName(field), field.getType().(ExportType), memberByteOffset(field),
  memberBitOffset(field), memberBitSize(field)
