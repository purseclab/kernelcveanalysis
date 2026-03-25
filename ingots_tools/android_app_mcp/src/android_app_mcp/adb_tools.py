from pathlib import Path
from shlex import quote
from tempfile import NamedTemporaryFile
from uuid import uuid4

from libadb import AdbClient


def read_text_file(adb: AdbClient, path: str, root: bool = False) -> str:
    data = adb.read_file(path)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Remote file is not valid UTF-8: {path}") from exc


def write_text_file(
    adb: AdbClient,
    path: str,
    content: str,
    root: bool = False,
    create_parents: bool = False,
) -> int:
    target = Path(path)
    parent = str(target.parent)

    with NamedTemporaryFile() as tmp:
        data = content.encode("utf-8")
        tmp.write(data)
        tmp.flush()

        if root:
            # adb push cannot put in root dir, stage in temporary dir
            # and copy to root location later
            temp_path = f"/data/local/tmp/android-app-mcp-{uuid4().hex}"
            adb.upload_file(Path(tmp.name), Path(temp_path))
            try:
                commands = []
                if create_parents and parent not in ("", "."):
                    commands.append(f"mkdir -p {quote(parent)}")
                commands.append(f"cp {quote(temp_path)} {quote(path)}")
                command = " && ".join(commands)
                adb.shell_text(command, root=True)
            finally:
                cleanup = f"rm -f {quote(temp_path)}"
                adb.run_shell(cleanup, root=True, check=False)
        else:
            if create_parents and parent not in ("", "."):
                command = f"mkdir -p {quote(parent)}"
                adb.shell_text(command, root=False)
            adb.upload_file(Path(tmp.name), Path(path))

    return len(data)
