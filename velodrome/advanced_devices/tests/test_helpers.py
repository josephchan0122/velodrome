from datetime import datetime

from velodrome.advanced_devices.helpers import (
    clear_ini_config_content, create_chsum_uuid,
)


def test_clear_ini_config_content():
    """Simple config format test.
    """

    data1 = """
    [main]
    test_value=1
    [test]
    data=1
    var=test data

    new=
    """

    data2 = """
    [main]
    test_value=1
    [test]
    data=1
    # comment
    var=test data
    new=
    """

    h1, _ = clear_ini_config_content(data1)
    h2, _ = clear_ini_config_content(data2)
    h3, _ = clear_ini_config_content("")
    assert h1 == h2
    assert h3
    assert h1 != h3


def test_create_chsum_uuid():
    """Simple test case.
    """

    data = [
        (1,),
        (1, 2),
        (1, 0),
        (1, False),
        (0, 0),
        (0,),
        (1, "st"),
        (datetime(2020, 1, 1), 1, (2, "1")),
        ("",),
        ("", "")
    ]

    result = [create_chsum_uuid(*arg).hex for arg in data]
    assert result == [
        "bbdae70a04c5b80d16be6b42713eb22e",
        "9a808c3ee8d01820cc66c5d237859c94",
        "e98a22f30af19f9d1b1ff05d9207572b",
        "a11d13b7925a0b7ce793d824876b5eb6",
        "524c06889b3e43286194691d857f6598",
        "02660417c256a6a222c1231c5bfe6f8b",
        "3c6ceb0d58e60e55d5961e8a7b4321f8",
        "e8978ebd00dba711727cc1d7f2844cd3",
        "bfd9025af25eafa6476eef851020b0e1",
        "b73910d7cfbca893097798d782c107a8",
    ]
