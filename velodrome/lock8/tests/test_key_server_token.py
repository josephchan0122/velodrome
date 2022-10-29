import time
import uuid

from velodrome.lock8.key_server_access import TokenGenerator


def test_correct_tokens():
    """Simple test with random password.
    """

    password_1 = f"{uuid.uuid4()}-{uuid.uuid4().int}"
    password_2 = f"{uuid.uuid4()}-{uuid.uuid4().int}"

    data_1 = {
        "user": "michael@noa.one",
        "user_uid": "1149e4b9-e805-4bfd-b7c2-8dbe5dc21f58",
        "correct": True,
        "organization": "noa",
    }

    data_2 = {
        "user": "michael@noa.one",
        "user_uid": "1149e4b9-e805-4bfd-b7c2-11be5dc21f58",
        "organization": "google",
    }

    generator = TokenGenerator(password_1)

    token_1_1 = generator.create_token(**data_1)
    token_1_2 = generator.create_token(**data_1)
    token_2_1 = generator.create_token(**data_2)
    token_2_2 = generator.create_token(**data_2)
    n = len(set([token_1_1, token_1_2, token_2_1, token_2_2]))
    assert n == 4

    assert len(token_2_2) < 400

    result, is_correct = generator.open_token(token_1_1)
    assert is_correct
    assert result == data_1
    result, is_correct = generator.open_token(token_1_2)
    assert is_correct
    assert result == data_1

    result, is_correct = generator.open_token(token_2_1)
    assert is_correct
    assert result == data_2
    result, is_correct = generator.open_token(token_2_1)
    assert is_correct
    assert result == data_2

    generator2 = TokenGenerator(password_2)

    token_3_1 = generator2.create_token(**data_1)
    token_3_2 = generator2.create_token(**data_1)

    result, is_correct = generator2.open_token(token_3_1)
    assert is_correct
    assert result == data_1
    result, is_correct = generator2.open_token(token_3_2)
    assert is_correct
    assert result == data_1

    result, is_correct = generator2.open_token(token_2_1)
    assert not is_correct
    assert result == {}
    result, is_correct = generator2.open_token(token_2_1)
    assert not is_correct
    assert result == {}

    result, is_correct = generator.open_token(token_3_1)
    assert not is_correct
    assert result == {}
    result, is_correct = generator.open_token(token_3_1)
    assert not is_correct
    assert result == {}

    generator3 = TokenGenerator(password_1, 1)
    token_4_1 = generator3.create_token(**data_1)
    time.sleep(1.01)
    result, is_correct = generator.open_token(token_4_1)
    assert not is_correct
    assert result == {}
