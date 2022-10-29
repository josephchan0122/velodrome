import os
import uuid

from velodrome.common.utils import (
    env_data, env_val, env_val_float, env_var_bool,
)


def test_env_methods(tmp_path_factory):
    file_path = "{}/file.dat".format(
        tmp_path_factory.mktemp(f"{uuid.uuid4()}")
    )

    field = "data_1"
    os.environ[field] = "8"
    assert env_val(field) == "8"
    assert not env_var_bool(field)
    os.environ[field] = "8.5"
    assert env_val_float(field) == 8.5
    os.environ[field] = "yes"
    assert env_var_bool(field)
    assert env_val_float(field) == 0

    assert env_data(field) == "yes"
    value = uuid.uuid4().hex
    with open(file_path, "w") as data_file:
        data_file.write(value)

    os.environ[field] = file_path
    assert env_data(field, error_return=True) == value
