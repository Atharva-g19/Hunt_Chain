from scopeguard.models.program import Program


def test_program_creation():
    program = Program(name="Example Program")

    assert program.name == "Example Program"