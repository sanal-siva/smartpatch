"""Locate a failing JSON path without building a second document or a source map.

The input must already have passed JSON decoding. Missing properties point to
their containing value; duplicate properties follow JSON's last-value behavior.
"""
import json
import re

_SPACE=re.compile(r'\s*')
_PUNCTUATION=re.compile(r'["{}\[\]]')
_SCALAR=re.compile(r'[^,}\]\s]+')
_MEMBER=re.compile(r'[A-Za-z_][A-Za-z_0-9-]*')


def format_path(parts):
    return '$'+''.join('['+str(part)+']' if isinstance(part,int) else
        '.'+part if _MEMBER.fullmatch(part) else '['+json.dumps(part)+']' for part in parts)


def path_parts(path):
    if isinstance(path,(tuple,list)):return tuple(path)
    parts=[];i=1
    while i<len(path):
        if path[i]=='.':
            match=_MEMBER.match(path,i+1)
            if not match:return ()
            parts.append(match.group());i=match.end()
        elif path[i]=='[':
            if path[i+1]=='"':
                value,end=json.decoder.scanstring(path,i+2);parts.append(value);i=end+1
            else:
                end=path.index(']',i);parts.append(int(path[i+1:end]));i=end+1
        else:return ()
    return tuple(parts)


def _skip_value(source,index):
    char=source[index]
    if char=='"':return json.decoder.scanstring(source,index+1)[1]
    if char not in '{[':return _SCALAR.match(source,index).end()
    depth=1;index+=1
    while depth:
        match=_PUNCTUATION.search(source,index);char=match.group();index=match.end()
        if char=='"':index=json.decoder.scanstring(source,index)[1]
        elif char in '{[':depth+=1
        else:depth-=1
    return index


def locate(source,parts):
    """Return one-based line/column of the closest existing value at ``parts``."""
    def position(index,remaining):
        start=_SPACE.match(source,index).end()
        if not remaining:return start
        char=source[start];wanted=remaining[0];found=start
        if char=='{' and isinstance(wanted,str):
            index=_SPACE.match(source,start+1).end()
            while source[index]!='}':
                key,index=json.decoder.scanstring(source,index+1)
                index=_SPACE.match(source,index).end()+1  # colon
                index=_SPACE.match(source,index).end()
                if key==wanted:found=position(index,remaining[1:])
                index=_SPACE.match(source,_skip_value(source,index)).end()
                if source[index]=='}':break
                index=_SPACE.match(source,index+1).end()
        elif char=='[' and isinstance(wanted,int):
            index=_SPACE.match(source,start+1).end();item=0
            while source[index]!=']':
                if item==wanted:return position(index,remaining[1:])
                index=_SPACE.match(source,_skip_value(source,index)).end();item+=1
                if source[index]==']':break
                index=_SPACE.match(source,index+1).end()
        return found
    index=position(0,tuple(parts))
    return source.count('\n',0,index)+1,index-source.rfind('\n',0,index)
