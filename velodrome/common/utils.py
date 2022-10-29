import os


def env_val(key: str) -> str:
    """Reading a environment variable as text.
    """
    return str(os.environ.get(key) or "").strip()


def env_val_float(key: str) -> float:
    """Reading a environment variable as float.
    """
    try:
        return float(env_val(key) or 0)
    except ValueError:
        return 0


def env_var_bool(key: str) -> bool:
    """Reading a environment variable as binary.
    """
    return env_val(key).upper() in (
        "TRUE", "ON", "YES", "OK", "1", "ACTIVE", "USE"
    )


def env_data(name: str, error_return: bool = False) -> str:
    """Read string from env or file if the env value is a file path.
    """
    value = env_val(name)
    try:
        if os.path.exists(value):
            with open(value) as data_file:
                value = data_file.read()
    except Exception as err:
        if error_return:
            value = f"value error: {err}"

    return value
