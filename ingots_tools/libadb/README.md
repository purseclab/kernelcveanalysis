# libadb

ADB utilities and tools for kernel exploitation research.

```python
from pathlib import Path

from libadb import AdbClient

adb = AdbClient()
other_device = AdbClient("127.0.0.1:5555")

adb.upload_tools()
output = adb.run_adb_command("id", root=True)
other_device.install_app(Path("app.apk"))
```
