from app.integration.process_field_extractors import extract_process_fields


def test_extracts_sysmon_process_fields():
    data = {
        "win": {
            "eventdata": {
                "commandLine": "powershell.exe -enc AAA",
                "parentCommandLine": "explorer.exe",
                "image": "powershell.exe",
                "parentImage": "explorer.exe",
                "processId": "100",
                "parentProcessId": "50",
                "hashes": "MD5=abc,SHA256=def",
            }
        }
    }

    fields = extract_process_fields(data)

    assert fields is not None
    assert fields.command_line == "powershell.exe -enc AAA"
    assert fields.parent_command_line == "explorer.exe"
    assert fields.process_name == "powershell.exe"
    assert fields.parent_process_name == "explorer.exe"
    assert fields.process_id == "100"
    assert fields.parent_process_id == "50"
    assert fields.process_hashes == "MD5=abc,SHA256=def"


def test_returns_none_when_no_command_line():
    assert extract_process_fields({"win": {"eventdata": {}}}) is None


def test_returns_none_for_non_sysmon_data_shape():
    assert extract_process_fields({"srcip": "203.0.113.5"}) is None


def test_returns_none_for_empty_data():
    assert extract_process_fields({}) is None
