import json, sys
with open(sys.argv[1]) as f:
    plan = json.load(f)
d = plan["data"]
print("technique:", d.get("technique"))
print("slab_cache:", d.get("slab_cache"))
print("target_struct:", d.get("target_struct"))
print("vuln_type:", d.get("vulnerability_type"))
steps = d.get("steps",[])
print(f"\nSTEPS ({len(steps)}):")
for s in steps:
    phase = s.get("phase","?")
    name = s.get("name","?")
    prov = s.get("provider","?")
    hint = str(s.get("code_hint",""))[:100]
    print(f"  {phase} | {name} | prov={prov}")
    if hint: print(f"    hint: {hint}")
