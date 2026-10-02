import hashlib
import json

import pytest

from app.services.json_source import format_path,path_parts,locate
from app.services.sbom_parser import SBOMParser,SBOMValidationError


def test_nested_component_error_identifies_original_nested_source_line():
    raw=b'''{
  "bomFormat":"CycloneDX", "specVersion":"1.6",
  "components":[{
    "type":"container", "name":"bgp",
    "components":[{
      "type":"library",
      "name": 47
    }]
  }]
}'''
    with pytest.raises(SBOMValidationError) as error:SBOMParser().load_bytes(raw)
    assert error.value.path=='$.components[0].components[0].name'
    assert (error.value.line,error.value.column)==(7,15)


def test_offline_schema_error_reports_source_line_and_path():
    raw=b'''{
  "bomFormat":"CycloneDX", "specVersion":"1.6",
  "components":[{
    "type":"library", "name":"curl",
    "hashes":[{
      "alg":"SHA-256",
      "content":"not-a-sha256"
    }]
  }]
}'''
    with pytest.raises(SBOMValidationError) as error:SBOMParser().load_bytes(raw)
    assert error.value.path=='$.components[0].hashes[0].content'
    assert error.value.line==7 and 'line 7' in str(error.value)


def test_required_property_points_to_containing_value_without_invented_line():
    raw=b'''{
  "bomFormat":"CycloneDX", "specVersion":"1.6",
  "components":[
    {"type":"library"}
  ]
}'''
    with pytest.raises(SBOMValidationError) as error:SBOMParser().load_bytes(raw)
    assert error.value.path=='$.components[0].name'
    assert (error.value.line,error.value.column)==(4,5)


def test_duplicate_member_uses_last_value_and_unicode_columns_are_characters():
    source='{"name": "okay",\n "é": "\\\" } [", "name": 17}'
    assert json.loads(source)['name']==17
    line,column=locate(source,('name',))
    assert line==2 and source.splitlines()[1][column-1:]=='17}'


@pytest.mark.parametrize('parts',[('a.b',1,'quote"key'),('array',0),('dash-key',),()])
def test_json_path_round_trip_for_escaped_keys(parts):
    assert path_parts(format_path(parts))==parts


def test_locator_skips_unrelated_nested_values_and_falls_back_to_parent():
    source='{"ignored": [{"x": "\\\"} ["}, null, true, -1.3e2],\n "target": {"a.b": [false,\n {"quote\\\"key": 2}]}}'
    json.loads(source)
    line,column=locate(source,('target','a.b',1,'quote"key'))
    assert line==3 and source.splitlines()[line-1][column-1:].startswith('2')
    parent=locate(source,('target','a.b',1))
    assert locate(source,('target','a.b',1,'absent'))==parent


def test_raw_loader_preserves_digest_and_dict_validation_has_no_original_line():
    raw=b'\xef\xbb\xbf{ "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [] }'
    parser=SBOMParser();document=parser.load_bytes(raw)
    assert parser.source_sha256==hashlib.sha256(raw).hexdigest()
    assert document==parser.current_sbom
    with pytest.raises(SBOMValidationError) as error:
        parser.load_sbom({'bomFormat':'CycloneDX','specVersion':'1.6','components':[{'type':'library'}]})
    assert error.value.line is None and parser.source_sha256 is None


def test_component_array_error_and_json_syntax_error_have_positions():
    with pytest.raises(SBOMValidationError) as error:
        SBOMParser().load_bytes(b'{\n "bomFormat":"CycloneDX", "specVersion":"1.6",\n "components": {}\n}')
    assert error.value.path=='$.components' and error.value.line==3
    with pytest.raises(SBOMValidationError) as error:SBOMParser().load_bytes(b'{\n "components": }')
    assert error.value.line==2

