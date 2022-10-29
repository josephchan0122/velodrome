import configparser
import hashlib
import io
import re
import typing
import uuid


def get_version(data: str) -> typing.Tuple[int, int, int]:
    """Three part format of version.
    """
    part_m = part_mi = part_p = 0
    if data:
        parts = re.split(r"[,.]{1}", data)
        if len(parts) == 3:
            try:
                part_m, part_mi, part_p = map(
                    int, map(str.strip, parts)
                )
            except (ValueError, TypeError):
                pass

    return (part_m, part_mi, part_p)


def clear_ini_config_content(data: str) -> typing.Tuple[str, str]:
    """Check valid configuration and return the checksum and content.
    """
    chsm = content = ""
    buffer = io.StringIO()
    config = configparser.ConfigParser()
    try:
        config.read_string(data)
        # rewrite the config content to make a checksum
        config.write(buffer)
        buffer.seek(0)
        content = buffer.read()
        chsm = hashlib.md5(content.encode()).hexdigest()
    except Exception:
        pass

    return chsm, content


def create_chsum_uuid(*parts: typing.Any) -> uuid.UUID:
    """Create a 128 bit uuid using the hash function.
    """
    # start random, do not change
    hs = hashlib.md5(f"noa-{len(parts)}".encode())
    for part in parts:
        hs.update(str(part).encode())

    return uuid.UUID(hs.hexdigest())
